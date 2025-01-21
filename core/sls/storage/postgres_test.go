package storage

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
)

func TestPostgresIsQuarantined(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	query := `SELECT "q"\."is_released" FROM "sls"\."quarantine" AS "q" WHERE \(tx_hash = '0x[0-9a-fA-F]{64}'\)`

	tests := []struct {
		name      string
		txHash    common.Hash
		mockSetup func(mock sqlmock.Sqlmock)
		want      bool
		wantErr   bool
	}{
		{
			name:   "Transaction is quarantined",
			txHash: common.HexToHash("0xabcd"),
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"is_released"}).AddRow(false)
				mock.ExpectQuery(query).WillReturnRows(rows)
			},
			want:    true,
			wantErr: false,
		},
		{
			name:   "Transaction is released",
			txHash: common.HexToHash("0x1234"),
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"is_released"}).AddRow(true)
				mock.ExpectQuery(query).WillReturnRows(rows)
			},
			want:    false,
			wantErr: false,
		},
		{
			name:   "Transaction not found",
			txHash: common.HexToHash("0xdeadbeef"),
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WillReturnError(sql.ErrNoRows)
			},
			want:    false,
			wantErr: false,
		},
		{
			name:   "SQL Error",
			txHash: common.HexToHash("0xdeadbeef"),
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(query).WillReturnError(errors.New("real sql error"))
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, mock, err := sqlmock.New()
			assert.NoError(t, err)

			tt.mockSetup(mock)

			pg := NewPostgres(db)
			result, err := pg.IsQuarantined(ctx, tt.txHash)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, result)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPostgresAll(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	offset := 0
	limit := 10
	addressHex := "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
	fromAddress := common.HexToAddress(addressHex)

	tests := []struct {
		name      string
		offset    int
		limit     int
		from      *common.Address
		mockSetup func(mock sqlmock.Sqlmock)
		want      []*model.Quarantine
		wantCount int
		wantErr   bool
	}{
		{
			name:   "Fetch quarantines successfully with from address",
			offset: offset,
			limit:  limit,
			from:   &fromAddress,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"tx_hash", "from_addr"}).
					AddRow("0xabcd", addressHex)
				mock.ExpectQuery(`SELECT "q"\."expires_on", "q"\."tx_data", "q"\."tx_hash", "q"\."quarantined_at", "q"\."quarantined_reason", "q"\."quarantined_by", "q"\."released_at", "q"\."released_reason", "q"\."released_by", "q"\."is_released", "q"\."from_addr", "q"\."nonce", "q"\."loss", "q"\."value", "q"\."quarantine_type" FROM "sls"\."quarantine" AS "q" WHERE \(from_addr = '0x[a-fA-F0-9]{40}'\) ORDER BY "quarantined_at" DESC LIMIT 10`).
					WillReturnRows(rows)
				rowsCount := sqlmock.NewRows([]string{"count"}).
					AddRow("1")
				mock.ExpectQuery(`SELECT count\(\*\) FROM "sls"\."quarantine" AS "q" WHERE \(from_addr = '0x[a-fA-F0-9]{40}'\)`).
					WillReturnRows(rowsCount)
			},
			want:      []*model.Quarantine{{TxHash: "0xabcd", From: addressHex}},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:   "Fetch quarantines successfully without from address",
			offset: offset,
			limit:  limit,
			from:   nil,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"tx_hash", "from_addr"}).
					AddRow("0xabcd", addressHex)
				mock.ExpectQuery(`SELECT "q"\."expires_on", "q"\."tx_data", "q"\."tx_hash", "q"\."quarantined_at", "q"\."quarantined_reason", "q"\."quarantined_by", "q"\."released_at", "q"\."released_reason", "q"\."released_by", "q"\."is_released", "q"\."from_addr", "q"\."nonce", "q"\."loss", "q"\."value", "q"\."quarantine_type" FROM "sls"\."quarantine" AS "q" ORDER BY "quarantined_at" DESC LIMIT 10`).
					WillReturnRows(rows)
				rowsCount := sqlmock.NewRows([]string{"count"}).
					AddRow("1")
				mock.ExpectQuery(`SELECT count\(\*\) FROM "sls"\."quarantine" AS "q"`).
					WillReturnRows(rowsCount)
			},
			want:      []*model.Quarantine{{TxHash: "0xabcd", From: addressHex}},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:   "Fetch quarantines successfully with offset",
			offset: 5,
			limit:  limit,
			from:   nil,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"tx_hash", "from_addr"}).
					AddRow("0xabcd", addressHex)
				mock.ExpectQuery(`SELECT "q"\."expires_on", "q"\."tx_data", "q"\."tx_hash", "q"\."quarantined_at", "q"\."quarantined_reason", "q"\."quarantined_by", "q"\."released_at", "q"\."released_reason", "q"\."released_by", "q"\."is_released", "q"\."from_addr", "q"\."nonce", "q"\."loss", "q"\."value", "q"\."quarantine_type" FROM "sls"\."quarantine" AS "q" ORDER BY "quarantined_at" DESC LIMIT 10 OFFSET 5`).
					WillReturnRows(rows)
				rowsCount := sqlmock.NewRows([]string{"count"}).
					AddRow("1")
				mock.ExpectQuery(`SELECT count\(\*\) FROM "sls"\."quarantine" AS "q"`).
					WillReturnRows(rowsCount)
			},
			want:      []*model.Quarantine{{TxHash: "0xabcd", From: addressHex}},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:   "Handle error during query execution",
			offset: offset,
			limit:  limit,
			from:   nil,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT "q"\."expires_on", "q"\."tx_data", "q"\."tx_hash", "q"\."quarantined_at", "q"\."quarantined_reason", "q"\."quarantined_by", "q"\."released_at", "q"\."released_reason", "q"\."released_by", "q"\."is_released", "q"\."from_addr", "q"\."nonce", "q"\."loss", "q"\."value", "q"\."quarantine_type" FROM "sls"\."quarantine" AS "q" ORDER BY "quarantined_at" DESC LIMIT 10`).
					WillReturnError(errors.New("query error"))
			},
			want:      []*model.Quarantine{{TxHash: "0xabcd", From: addressHex}},
			wantCount: 0,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, mock, err := sqlmock.New()
			assert.NoError(t, err)

			tt.mockSetup(mock)

			pg := NewPostgres(db)
			result, count, err := pg.All(ctx, tt.offset, tt.limit, tt.from)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantCount, count)
				assert.EqualValues(t, tt.want, result)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPostgresQuarantined(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	addressHex := "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
	fromAddress := common.HexToAddress(addressHex)

	tests := []struct {
		name      string
		from      *common.Address
		mockSetup func(mock sqlmock.Sqlmock)
		want      []*model.Quarantine
		wantCount int
		wantErr   bool
	}{
		{
			name: "Fetch quarantines not released with from address",
			from: &fromAddress,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"tx_hash", "from_addr"}).
					AddRow("0xabcd", addressHex)
				mock.ExpectQuery(`SELECT "q"\."expires_on", "q"\."tx_data", "q"\."tx_hash", "q"\."quarantined_at", "q"\."quarantined_reason", "q"\."quarantined_by", "q"\."released_at", "q"\."released_reason", "q"\."released_by", "q"\."is_released", "q"\."from_addr", "q"\."nonce", "q"\."loss", "q"\."value", "q"\."quarantine_type" FROM "sls"\."quarantine" AS "q" WHERE \(is_released = false\) AND \(from_addr = '[a-zA-Z0-9]+'\) ORDER BY "quarantined_at" DESC`).
					WillReturnRows(rows)
				rowsCount := sqlmock.NewRows([]string{"count"}).
					AddRow("1")
				mock.ExpectQuery(`SELECT count\(\*\) FROM "sls"\."quarantine" AS "q"  WHERE \(is_released = false\) AND \(from_addr = '[a-zA-Z0-9]+'\)`).
					WillReturnRows(rowsCount)
			},
			want:      []*model.Quarantine{{TxHash: "0xabcd", From: addressHex}},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "Fetch quarantines not released without from address",
			from: nil,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"tx_hash", "from_addr"}).
					AddRow("0xabcd", addressHex)
				mock.ExpectQuery(`SELECT "q"\."expires_on", "q"\."tx_data", "q"\."tx_hash", "q"\."quarantined_at", "q"\."quarantined_reason", "q"\."quarantined_by", "q"\."released_at", "q"\."released_reason", "q"\."released_by", "q"\."is_released", "q"\."from_addr", "q"\."nonce", "q"\."loss", "q"\."value", "q"\."quarantine_type" FROM "sls"\."quarantine" AS "q" WHERE \(is_released = false\) ORDER BY "quarantined_at" DESC`).
					WillReturnRows(rows)
				rowsCount := sqlmock.NewRows([]string{"count"}).
					AddRow("1")
				mock.ExpectQuery(`SELECT count\(\*\) FROM "sls"\."quarantine" AS "q"  WHERE \(is_released = false\)`).
					WillReturnRows(rowsCount)
			},
			want:      []*model.Quarantine{{TxHash: "0xabcd", From: addressHex}},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "Handle error during query execution",
			from: nil,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT "q"\."expires_on", "q"\."tx_data", "q"\."tx_hash", "q"\."quarantined_at", "q"\."quarantined_reason", "q"\."quarantined_by", "q"\."released_at", "q"\."released_reason", "q"\."released_by", "q"\."is_released", "q"\."from_addr", "q"\."nonce", "q"\."loss", "q"\."value", "q"\."quarantine_type" FROM "sls"\."quarantine" AS "q" WHERE \(is_released = false\) ORDER BY "quarantined_at" DESC`).
					WillReturnError(errors.New("query error"))
			},
			want:      []*model.Quarantine{{TxHash: "0xabcd", From: addressHex}},
			wantCount: 0,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, mock, err := sqlmock.New()
			assert.NoError(t, err)

			tt.mockSetup(mock)

			pg := NewPostgres(db)
			result, count, err := pg.Quarantined(ctx, tt.from)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantCount, count)
				assert.EqualValues(t, tt.want, result)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPostgresFindByHash(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	addressHex := "0xacc0fd10c00512c4f50f5bf318d6f340836343a77d6e89670716d1db1b6b3f51"
	hash := common.HexToHash(addressHex)
	errConnection := errors.New("can't connect to database")

	tests := []struct {
		name      string
		txHash    common.Hash
		mockSetup func(mock sqlmock.Sqlmock)
		want      *model.Quarantine
		wantErr   error
	}{
		{
			name:   "Can't find transaction",
			txHash: hash,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT \"q\".\"expires_on\", \"q\".\"tx_data\", \"q\".\"tx_hash\", \"q\".\"quarantined_at\", \"q\".\"quarantined_reason\", \"q\".\"quarantined_by\", \"q\".\"released_at\", \"q\".\"released_reason\", \"q\".\"released_by\", \"q\".\"is_released\", \"q\".\"from_addr\", \"q\".\"nonce\", \"q\".\"loss\", \"q\".\"value\", \"q\".\"quarantine_type\" FROM \"sls\".\"quarantine\" AS \"q\" WHERE \(tx_hash = '[a-zA-Z0-9]+'\)`).
					WillReturnError(sql.ErrNoRows)
			},
			want:    nil,
			wantErr: ErrTransactionNotFound,
		},
		{
			name:   "Can't execute query",
			txHash: hash,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT \"q\".\"expires_on\", \"q\".\"tx_data\", \"q\".\"tx_hash\", \"q\".\"quarantined_at\", \"q\".\"quarantined_reason\", \"q\".\"quarantined_by\", \"q\".\"released_at\", \"q\".\"released_reason\", \"q\".\"released_by\", \"q\".\"is_released\", \"q\".\"from_addr\", \"q\".\"nonce\", \"q\".\"loss\", \"q\".\"value\", \"q\".\"quarantine_type\" FROM \"sls\".\"quarantine\" AS \"q\" WHERE \(tx_hash = '[a-zA-Z0-9]+'\)`).
					WillReturnError(errConnection)
			},
			want:    nil,
			wantErr: errConnection,
		},
		{
			name:   "All Good",
			txHash: hash,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"tx_hash", "from_addr"}).
					AddRow("0xabcd", addressHex)
				mock.ExpectQuery(`SELECT \"q\".\"expires_on\", \"q\".\"tx_data\", \"q\".\"tx_hash\", \"q\".\"quarantined_at\", \"q\".\"quarantined_reason\", \"q\".\"quarantined_by\", \"q\".\"released_at\", \"q\".\"released_reason\", \"q\".\"released_by\", \"q\".\"is_released\", \"q\".\"from_addr\", \"q\".\"nonce\", \"q\".\"loss\", \"q\".\"value\", \"q\".\"quarantine_type\" FROM \"sls\".\"quarantine\" AS \"q\" WHERE \(tx_hash = '[a-zA-Z0-9]+'\)`).
					WillReturnRows(rows)
			},
			want:    &model.Quarantine{TxHash: "0xabcd", From: addressHex},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, mock, err := sqlmock.New()
			assert.NoError(t, err)

			tt.mockSetup(mock)

			pg := NewPostgres(db)
			result, err := pg.FindByHash(ctx, tt.txHash)

			assert.Equal(t, tt.wantErr, err)
			assert.EqualValues(t, tt.want, result)

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestGetIntegrityListAddresses(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name      string
		mockSetup func(mock sqlmock.Sqlmock)
		want      []common.Address
		wantErr   error
	}{
		{
			name: "Successfully return addresses",
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"address"}).
					AddRow("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
				mock.ExpectQuery(`SELECT \"i\".\"address\" FROM \"sls\".\"integrity_address\" AS \"i\"`).
					WillReturnRows(rows)
			},
			want:    []common.Address{common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, mock, err := sqlmock.New()
			assert.NoError(t, err)

			tt.mockSetup(mock)

			pg := NewPostgres(db)
			result, err := pg.GetIntegrityListAddresses(ctx)

			assert.Equal(t, tt.wantErr, err)
			assert.EqualValues(t, tt.want, result)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestRemoveIntegrityListAddresses(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name      string
		addresses []common.Address
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   error
	}{
		{
			name: "Successfully remove address",
			addresses: []common.Address{
				common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
			},
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`DELETE FROM "sls"\."integrity_address" AS "i" WHERE "i"\."address" IN \('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'\)`).
					WillReturnResult(sqlmock.NewResult(1, 1))

			},
			wantErr: nil,
		},
		{
			name: "Successfully remove addresses",
			addresses: []common.Address{
				common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
				common.HexToAddress("0x40ea7581ed45Bf55f255b465c59ccfD298fC3C79"),
			},
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`DELETE FROM "sls"\."integrity_address" AS "i" WHERE "i"\."address" IN \('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', '0x40ea7581ed45Bf55f255b465c59ccfD298fC3C79'\)`).
					WillReturnResult(sqlmock.NewResult(1, 1))

			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, mock, err := sqlmock.New()
			assert.NoError(t, err)

			tt.mockSetup(mock)

			pg := NewPostgres(db)
			err = pg.RemoveIntegrityListAddresses(ctx, tt.addresses)
			assert.Equal(t, tt.wantErr, err)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestAddIntegrityListAddresses(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name      string
		addresses []common.Address
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   error
	}{
		{
			name: "Successfully add address",
			addresses: []common.Address{
				common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
			},
			mockSetup: func(mock sqlmock.Sqlmock) {

				mock.ExpectExec(`INSERT INTO "sls"\."integrity_address" \("address"\) VALUES \('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'\)`).
					WillReturnResult(sqlmock.NewResult(1, 1))

			},
			wantErr: nil,
		},
		{
			name: "Successfully add addresses",
			addresses: []common.Address{
				common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
				common.HexToAddress("0xa0B86991C6218b36c1d19d4A2E9eB0CE3606eb49"),
			},
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`INSERT INTO "sls"\."integrity_address" \("address"\) VALUES \('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'\), \('0xa0B86991C6218b36c1d19d4A2E9eB0CE3606eb49'\)`).
					WillReturnResult(sqlmock.NewResult(1, 2))
			},

			wantErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, mock, err := sqlmock.New()
			assert.NoError(t, err)

			tt.mockSetup(mock)

			pg := NewPostgres(db)
			err = pg.AddIntegrityListAddresses(ctx, tt.addresses)
			assert.Equal(t, tt.wantErr, err)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPostgresAddTransactionResult(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	txHash := "0x1111111111111111111111111111111111111111111111111111111111111111"

	dbError := errors.New("db error")

	tests := []struct {
		name      string
		txResult  *model.TransactionResult
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   error
	}{
		{
			name: "Successfully store a transaction result",
			txResult: &model.TransactionResult{
				TxHash:      txHash,
				Quarantined: true,
			},
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"created_on"}).AddRow(time.Now())
				mock.ExpectQuery(`INSERT INTO "sls"."transaction_results" AS "tr" ("tx_hash", "quarantined", "created_on") VALUES ('0x1111111111111111111111111111111111111111111111111111111111111111', TRUE, DEFAULT) ON CONFLICT (tx_hash) DO UPDATE SET quarantined = EXCLUDED.quarantined RETURNING "created_on"`).
					WillReturnRows(rows)
			},
			wantErr: nil,
		},
		{
			name: "Error when storing transaction result",
			txResult: &model.TransactionResult{
				TxHash:      txHash,
				Quarantined: true,
			},
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`INSERT INTO "sls"."transaction_results" AS "tr" ("tx_hash", "quarantined", "created_on") VALUES ('0x1111111111111111111111111111111111111111111111111111111111111111', TRUE, DEFAULT) ON CONFLICT (tx_hash) DO UPDATE SET quarantined = EXCLUDED.quarantined RETURNING "created_on"`).
					WillReturnError(dbError)
			},
			wantErr: dbError,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			assert.NoError(t, err)

			tt.mockSetup(mock)

			pg := NewPostgres(db)
			err = pg.AddTransactionResult(ctx, tt.txResult)
			assert.Equal(t, tt.wantErr, err)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPostgresTrustListAddresses(t *testing.T) {
	ctx := context.Background()
	addresses := []common.Address{
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
	}

	tests := []struct {
		name      string
		operation string
		addresses []common.Address
		mockSetup func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name:      "Successfully add trusted addresses",
			operation: "add",
			addresses: addresses,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`INSERT INTO "sls"."trust_list" \("address", "created_at"\) VALUES \('0x1111111111111111111111111111111111111111', DEFAULT\), \('0x2222222222222222222222222222222222222222', DEFAULT\) RETURNING "created_at"`).
					WillReturnRows(sqlmock.NewRows([]string{"created_at"}).AddRow(time.Now()).AddRow(time.Now()))
			},
			wantErr: false,
		},
		{
			name:      "Successfully remove trusted addresses",
			operation: "remove",
			addresses: addresses,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`DELETE FROM "sls"."trust_list" AS "t" WHERE "t"."address" IN \('0x1111111111111111111111111111111111111111', '0x2222222222222222222222222222222222222222'\)`).
					WillReturnResult(sqlmock.NewResult(0, 2))
			},
			wantErr: false,
		},
		{
			name:      "Successfully get trusted addresses",
			operation: "get",
			addresses: addresses,
			mockSetup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"address", "created_at"}).
					AddRow("0x1111111111111111111111111111111111111111", time.Now()).
					AddRow("0x2222222222222222222222222222222222222222", time.Now())
				mock.ExpectQuery(`SELECT "t"."address", "t"."created_at" FROM "sls"."trust_list" AS "t"`).
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name:      "Error when adding trusted addresses",
			operation: "add",
			addresses: addresses,
			mockSetup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`INSERT INTO "sls"."trust_list" \("address", "created_at"\) VALUES \('0x1111111111111111111111111111111111111111', DEFAULT\), \('0x2222222222222222222222222222222222222222', DEFAULT\) RETURNING "created_at"`).
					WillReturnError(errors.New("database error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			assert.NoError(t, err)
			defer db.Close()

			tt.mockSetup(mock)

			pg := NewPostgres(db)

			var testErr error
			switch tt.operation {
			case "add":
				testErr = pg.AddTrustListAddresses(ctx, tt.addresses)
			case "remove":
				testErr = pg.RemoveTrustListAddresses(ctx, tt.addresses)
			case "get":
				_, testErr = pg.GetTrustListAddresses(ctx)
			}

			if tt.wantErr {
				assert.Error(t, testErr)
			} else {
				assert.NoError(t, testErr)
			}

			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}
