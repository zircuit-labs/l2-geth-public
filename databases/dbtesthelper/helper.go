//go:build integration

package dbtesthelper

/*
Package dbtesthelper provides a test database for use in unit tests.

	testDB, err := dbtesthelper.NewTestDatabase()
	defer testDB.Stop()
	testDB.Start()
	testDB.CreateNewTestDb()
	testDB.Migrate()
	db, err := sql.Open("pg", testDB.ConnectionString())
	if err != nil {
		return err
	}
	db.Exec("INSERT INTO ...")
*/

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	_ "github.com/uptrace/bun/driver/pgdriver"
	"github.com/zircuit-labs/l2-geth-public/databases"
	"github.com/zircuit-labs/zkr-go-common/xerrors/stacktrace"
)

// NilLogger is a logger that does nothing.
type NilLogger struct{}

func (d NilLogger) Printf(format string, v ...interface{}) {
}

type TestDatabase struct {
	adminSqlDB *sql.DB
	container  testcontainers.Container
	config     DbConf
}

var (
	username = "postgres"
	password = "postgres"
	image    = "postgres:16.2-alpine"
	logMsg   = "database system is ready to accept connections"
)

func getSchemas(schemasPath string) ([]string, error) {
	files, err := getSchemaFiles(schemasPath)
	if err != nil {
		return nil, err
	}

	schemas := make([]string, 0)
	for _, file := range files {

		c, err := databases.Schemas.ReadFile(file)
		if err != nil {
			return nil, err
		}

		schemas = append(schemas, string(c))
	}

	return schemas, nil
}

func getSchemaFiles(path string) ([]string, error) {
	var files []string
	if err := fs.WalkDir(databases.Schemas, path, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".sql") {
			return nil
		}

		files = append(files, path)

		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

type DbConf struct {
	Username      string
	Password      string
	Scheme        string
	Port          int
	TestDatabase  string
	AdminDatabase string
	mappedHost    string
	mappedPort    int
	flags         map[string][]string
}

func (c *DbConf) String(isAdmin bool) string {
	dsn := url.URL{
		User:     url.UserPassword(c.Username, c.Password),
		Scheme:   c.Scheme,
		Host:     fmt.Sprintf("%s:%d", c.mappedHost, c.mappedPort),
		Path:     c.TestDatabase,
		RawQuery: url.Values(c.flags).Encode(),
	}
	if isAdmin {
		dsn.Path = c.AdminDatabase
	}
	return dsn.String()
}

func (c *DbConf) Mapped(mappedHost string, mappedPort int) {
	c.mappedHost = mappedHost
	c.mappedPort = mappedPort
}

func NewConfig() DbConf {
	id := strings.ToLower(ulid.Make().String())
	dbName := fmt.Sprintf("pgtest_%s", id)

	return DbConf{
		Username:      username,
		Password:      password,
		Scheme:        "postgresql",
		Port:          5432,
		TestDatabase:  dbName,
		AdminDatabase: "postgres",
		mappedHost:    "",
		mappedPort:    0,
		flags: map[string][]string{
			"sslmode":           {"disable"},
			"statement_timeout": {"6000"}, // 6s
			"lock_timeout":      {"5000"}, // 5s: less than the statement_timeout in order to test lock functionality
		},
	}
}

func NewTestDatabase() (*TestDatabase, error) {
	config := NewConfig()
	ctx := context.Background()
	natPort := fmt.Sprintf("%d/tcp", config.Port) // Setup and startup container
	req := testcontainers.ContainerRequest{
		Image:        image,
		ExposedPorts: []string{natPort},
		Env: map[string]string{
			"POSTGRES_PASSWORD": config.Password,
			"POSTGRES_USER":     config.Username,
			"POSTGRES_DB":       config.AdminDatabase,
		},
		WaitingFor: wait.ForLog(logMsg).
			WithPollInterval(100 * time.Millisecond).
			WithOccurrence(2),
	}
	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
			Logger:           NilLogger{},
		},
	)
	if err != nil {
		return nil, stacktrace.Wrap(err)
	}

	mp, err := container.MappedPort(ctx, nat.Port(natPort))
	if err != nil {
		return nil, stacktrace.Wrap(err)
	}
	ma, err := container.Host(ctx)
	if err != nil {
		return nil, stacktrace.Wrap(err)
	}

	// Note the containers mapped host and port
	config.Mapped(ma, mp.Int())
	return &TestDatabase{container: container, config: config}, nil
}

func (t *TestDatabase) Start() error {
	db, err := sql.Open("pg", t.config.String(true))
	if err != nil {
		return err
	}
	t.adminSqlDB = db

	return nil
}

func (t *TestDatabase) CreateNewTestDb() error {
	query := fmt.Sprintf(`
	CREATE DATABASE %s;
	`, t.config.TestDatabase)
	_, err := t.adminSqlDB.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (t *TestDatabase) ResetTestDb() error {
	query := fmt.Sprintf(`
	DROP DATABASE %s WITH (FORCE);
	`, t.config.TestDatabase)
	_, err := t.adminSqlDB.Exec(query)
	if err != nil {
		return err
	}

	query = `SELECT rolname
	FROM pg_roles
	WHERE
		rolname NOT LIKE 'pg%'
		AND rolname != 'postgres';`
	result, err := t.adminSqlDB.Query(query)
	if err != nil {
		return err
	}
	builder := strings.Builder{}
	for result.Next() {
		var roleName string
		if err := result.Scan(&roleName); err != nil {
			return err
		}
		builder.WriteString("DROP ROLE \"")
		builder.WriteString(roleName)
		builder.WriteString("\";\n")
	}

	query = builder.String()
	if builder.Len() != 0 {
		_, err = t.adminSqlDB.Exec(query)
		if err != nil {
			return err
		}
	}

	return nil
}

// Migrate runs migrations.
func (t *TestDatabase) Migrate(schemasPath string) error {
	// Make sure to run the migrations using the clientSqlDB
	db, err := sql.Open("pg", t.config.String(false))
	if err != nil {
		return err
	}

	schemas, err := getSchemas(schemasPath)
	if err != nil {
		return err
	}

	for _, schema := range schemas {
		_, err = db.Exec(schema)
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *TestDatabase) Stop() error {
	return t.container.Terminate(context.Background())
}

func (t *TestDatabase) ConnectionString() string {
	return t.config.String(false)
}

func (t *TestDatabase) AdminConnectionString() string {
	return t.config.String(true)
}

// SetupSuite which is part of SetupAllSuite, should be run before the tests in the suite are run.
func SetupSuite(t *testing.T) *TestDatabase {
	t.Helper()
	db, err := NewTestDatabase()
	require.NoError(t, err)
	err = db.Start()
	require.NoError(t, err)

	return db
}

// TearDownSuite which is part of TearDownAllSuite, should be run after all the tests in the suite have been run.
func TearDownSuite(t *testing.T, db *TestDatabase) {
	t.Helper()
	err := db.Stop()
	require.NoError(t, err)
}
