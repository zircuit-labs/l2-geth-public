package main

import (
	"errors"
	"fmt"

	"github.com/urfave/cli/v2"
	"github.com/zircuit-labs/l2-geth/cmd/utils"
	"github.com/zircuit-labs/l2-geth/common/hexutil"
	"github.com/zircuit-labs/l2-geth/internal/flags"
	"github.com/zircuit-labs/l2-geth/log"
)

var zktrieCommand = &cli.Command{
	Name:        "zktrie",
	Usage:       "A set of zktrie tree management commands",
	Description: "",
	Subcommands: []*cli.Command{
		{
			Name:   "clean",
			Usage:  "clean ZkTrie related keys from the database",
			Action: cleanZkTrie,
			Flags:  flags.Merge(utils.NetworkFlags, utils.DatabaseFlags),
			Description: `
geth zktrie clean
This command cleans **ALL** ZkTrie related keys from the database.
In Zircuit l2-geth ZkTrie index prefixes are - iZK and iZKM in bytes equivalent.
 `,
		},
	},
}

func cleanZkTrie(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, false)
	defer chaindb.Close()

	if ctx.NArg() != 0 {
		log.Error("Too many arguments given")
		return errors.New("too many arguments")
	}

	log.Info("Starting cleaning ZkTrie state.")

	for _, prefix := range [][]byte{
		[]byte("iZK"),
		[]byte("iZKM"),
	} {
		iterator := chaindb.NewIterator(prefix, nil)
		log.Info("Cleaning ZkTrie state", "prefix", string(prefix))
		defer iterator.Release()

		for iterator.Next() {
			log.Trace("Cleaning ZkTrie state", "prefix", string(prefix), "key", hexutil.Encode(iterator.Key()))
			if err := chaindb.Delete(iterator.Key()); err != nil {
				log.Error("Failed to delete key", "key", string(iterator.Key()), "err", err)
				return fmt.Errorf("failed to delete key %s: %w", string(iterator.Key()), err)
			}
		}

		if err := iterator.Error(); err != nil {
			log.Error("Iterator failed", "key", string(iterator.Key()), "err", err)
			return fmt.Errorf("iterator failed: %w", err)
		}

		log.Info("Cleaned ZkTrie state", "prefix", string(prefix))
	}

	log.Info("Finished cleaning ZkTrie state.")
	return nil
}
