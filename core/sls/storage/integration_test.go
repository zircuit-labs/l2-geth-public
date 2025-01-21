//go:build integration

package storage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/storage"
	"github.com/zircuit-labs/l2-geth-public/databases/dbtesthelper"
)

type StoreTestSuite struct {
	suite.Suite
	db    *dbtesthelper.TestDatabase
	store storage.Storage
}

func (suite *StoreTestSuite) SetupSuite() {
	db := dbtesthelper.SetupSuite(suite.T())
	suite.db = db
}

func (suite *StoreTestSuite) SetupTest() {
	t := suite.T()
	db := suite.db
	t.Helper()
	t.Cleanup(func() {
		err := db.ResetTestDb()
		require.NoError(t, err)
	})

	err := db.CreateNewTestDb()
	require.NoError(t, err)

	err = db.Migrate("sls")
	require.NoError(t, err)

	dbdsn := db.ConnectionString()

	require.NoError(t, err)
	store, err := storage.NewStorage(context.Background(), storage.Config{DSN: dbdsn})
	require.NoError(t, err)
	suite.store = store
}

func (suite *StoreTestSuite) TearDownSuite() {
	dbtesthelper.TearDownSuite(suite.T(), suite.db)
}

func TestStoreTestSuite(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(StoreTestSuite))
}

func (suite *StoreTestSuite) TestTrustList() {
	t := suite.T()

	ctx := context.Background()
	addresses := []common.Address{
		common.HexToAddress("0x1"),
		common.HexToAddress("0x2"),
		common.HexToAddress("0x3"),
	}

	trustList, err := suite.store.GetTrustListAddresses(ctx)
	require.NoError(t, err)
	require.Empty(t, trustList)

	err = suite.store.AddTrustListAddresses(ctx, addresses)
	require.NoError(t, err)

	trustList, err = suite.store.GetTrustListAddresses(ctx)
	require.NoError(t, err)
	require.Equal(t, addresses, trustList)
}

func (suite *StoreTestSuite) TestAddAndRemoveTrustList() {
	t := suite.T()

	ctx := context.Background()
	addresses := []common.Address{
		common.HexToAddress("0x1"),
		common.HexToAddress("0x2"),
		common.HexToAddress("0x3"),
	}

	// Initially, the trust list should be empty
	trustList, err := suite.store.GetTrustListAddresses(ctx)
	require.NoError(t, err)
	require.Empty(t, trustList)

	// Test adding an empty list of addresses
	err = suite.store.AddTrustListAddresses(ctx, []common.Address{})
	require.NoError(t, err)

	// Verify that the trust list is still empty
	trustList, err = suite.store.GetTrustListAddresses(ctx)
	require.NoError(t, err)
	require.Empty(t, trustList)

	// Add addresses to the trust list
	err = suite.store.AddTrustListAddresses(ctx, addresses)
	require.NoError(t, err)

	// Adding same addresses again should error
	err = suite.store.AddTrustListAddresses(ctx, addresses)
	require.Error(t, err)

	// Check if addresses were added correctly
	trustList, err = suite.store.GetTrustListAddresses(ctx)
	require.NoError(t, err)
	require.Equal(t, addresses, trustList)

	// Remove one address from the trust list
	addressToRemove := common.HexToAddress("0x2")
	err = suite.store.RemoveTrustListAddresses(ctx, []common.Address{addressToRemove})
	require.NoError(t, err)

	// Check if the address was removed correctly
	trustList, err = suite.store.GetTrustListAddresses(ctx)
	require.NoError(t, err)
	require.Len(t, trustList, 2)
	require.NotContains(t, trustList, addressToRemove)
	require.Contains(t, trustList, common.HexToAddress("0x1"))
	require.Contains(t, trustList, common.HexToAddress("0x3"))

	// Remove the remaining addresses
	err = suite.store.RemoveTrustListAddresses(ctx, []common.Address{common.HexToAddress("0x1"), common.HexToAddress("0x3")})
	require.NoError(t, err)

	// Check if the trust list is empty again
	trustList, err = suite.store.GetTrustListAddresses(ctx)
	require.NoError(t, err)
	require.Empty(t, trustList)
}

func (suite *StoreTestSuite) TestAddressInTrustList() {
	t := suite.T()

	ctx := context.Background()
	trustedAddress := common.HexToAddress("0x1234567890123456789012345678901234567890")
	untrustedAddress := common.HexToAddress("0x0987654321098765432109876543210987654321")

	// Initially, both addresses should not be in the trust list
	isTrusted, err := suite.store.AddressInTrustList(ctx, trustedAddress)
	require.NoError(t, err)
	require.False(t, isTrusted)

	isTrusted, err = suite.store.AddressInTrustList(ctx, untrustedAddress)
	require.NoError(t, err)
	require.False(t, isTrusted)

	// Add one address to the trust list
	err = suite.store.AddTrustListAddresses(ctx, []common.Address{trustedAddress})
	require.NoError(t, err)

	// Check if the trusted address is now recognized as trusted
	isTrusted, err = suite.store.AddressInTrustList(ctx, trustedAddress)
	require.NoError(t, err)
	require.True(t, isTrusted)

	// Check if the untrusted address is still not trusted
	isTrusted, err = suite.store.AddressInTrustList(ctx, untrustedAddress)
	require.NoError(t, err)
	require.False(t, isTrusted)

	// Remove the address from the trust list
	err = suite.store.RemoveTrustListAddresses(ctx, []common.Address{trustedAddress})
	require.NoError(t, err)

	// Check if the previously trusted address is no longer trusted
	isTrusted, err = suite.store.AddressInTrustList(ctx, trustedAddress)
	require.NoError(t, err)
	require.False(t, isTrusted)
}

func (suite *StoreTestSuite) TestAddressesInIntegrityList() {
	t := suite.T()

	ctx := context.Background()
	address1 := common.HexToAddress("0x1234567890123456789012345678901234567890")
	address2 := common.HexToAddress("0x0987654321098765432109876543210987654321")
	address3 := common.HexToAddress("0xabcdef0123456789abcdef0123456789abcdef01")

	// Initially, no addresses should be in the integrity list
	inList, err := suite.store.AddressesInIntegrityList(ctx, []common.Address{address1, address2, address3})
	require.NoError(t, err)
	require.Empty(t, inList)

	// Add address1 and address2 to the integrity list
	err = suite.store.AddIntegrityListAddresses(ctx, []common.Address{address1, address2})
	require.NoError(t, err)

	// Check if any of the addresses are in the integrity list (should return address1 and address2)
	inList, err = suite.store.AddressesInIntegrityList(ctx, []common.Address{address1, address2, address3})
	require.NoError(t, err)
	require.ElementsMatch(t, []common.Address{address1, address2}, inList)

	// Check individual addresses
	inList, err = suite.store.AddressesInIntegrityList(ctx, []common.Address{address1})
	require.NoError(t, err)
	require.ElementsMatch(t, []common.Address{address1}, inList)

	inList, err = suite.store.AddressesInIntegrityList(ctx, []common.Address{address2})
	require.NoError(t, err)
	require.ElementsMatch(t, []common.Address{address2}, inList)

	inList, err = suite.store.AddressesInIntegrityList(ctx, []common.Address{address3})
	require.NoError(t, err)
	require.Empty(t, inList)

	// Remove address1 from the integrity list
	err = suite.store.RemoveIntegrityListAddresses(ctx, []common.Address{address1})
	require.NoError(t, err)

	// Check if any of the addresses are still in the integrity list (should return only address2)
	inList, err = suite.store.AddressesInIntegrityList(ctx, []common.Address{address1, address2, address3})
	require.NoError(t, err)
	require.ElementsMatch(t, []common.Address{address2}, inList)

	// Remove the remaining address from the integrity list
	err = suite.store.RemoveIntegrityListAddresses(ctx, []common.Address{address2})
	require.NoError(t, err)

	// Check if any of the addresses are in the integrity list (should be empty now)
	inList, err = suite.store.AddressesInIntegrityList(ctx, []common.Address{address1, address2, address3})
	require.NoError(t, err)
	require.Empty(t, inList)
}

func (suite *StoreTestSuite) TestAddressesInTrustList() {
	t := suite.T()

	ctx := context.Background()
	address1 := common.HexToAddress("0x1234567890123456789012345678901234567890")
	address2 := common.HexToAddress("0x0987654321098765432109876543210987654321")
	address3 := common.HexToAddress("0xabcdef0123456789abcdef0123456789abcdef01")

	// Initially, no addresses should be in the trust list
	inList, err := suite.store.AddressesInTrustList(ctx, []common.Address{address1, address2, address3})
	require.NoError(t, err)
	require.Empty(t, inList)

	// Add address1 and address2 to the trust list
	err = suite.store.AddTrustListAddresses(ctx, []common.Address{address1, address2})
	require.NoError(t, err)

	// Check if any of the addresses are in the trust list (should return address1 and address2)
	inList, err = suite.store.AddressesInTrustList(ctx, []common.Address{address1, address2, address3})
	require.NoError(t, err)
	require.ElementsMatch(t, []common.Address{address1, address2}, inList)

	// Check individual addresses
	inList, err = suite.store.AddressesInTrustList(ctx, []common.Address{address1})
	require.NoError(t, err)
	require.ElementsMatch(t, []common.Address{address1}, inList)

	inList, err = suite.store.AddressesInTrustList(ctx, []common.Address{address2})
	require.NoError(t, err)
	require.ElementsMatch(t, []common.Address{address2}, inList)

	inList, err = suite.store.AddressesInTrustList(ctx, []common.Address{address3})
	require.NoError(t, err)
	require.Empty(t, inList)

	// Remove address1 from the trust list
	err = suite.store.RemoveTrustListAddresses(ctx, []common.Address{address1})
	require.NoError(t, err)

	// Check if any of the addresses are still in the trust list (should return only address2)
	inList, err = suite.store.AddressesInTrustList(ctx, []common.Address{address1, address2, address3})
	require.NoError(t, err)
	require.ElementsMatch(t, []common.Address{address2}, inList)

	// Remove the remaining address from the trust list
	err = suite.store.RemoveTrustListAddresses(ctx, []common.Address{address2})
	require.NoError(t, err)

	// Check if any of the addresses are in the trust list (should be empty now)
	inList, err = suite.store.AddressesInTrustList(ctx, []common.Address{address1, address2, address3})
	require.NoError(t, err)
	require.Empty(t, inList)
}
