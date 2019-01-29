#!/bin/bash

TESTNET_ROOT_DIR="/home/jedrzej/tendermint"
TESTNET_FOLDER="mytestnet"

NODE_0_NAME="node0"
NODE_1_NAME="node1"
NODE_2_NAME="node2"
NODE_3_NAME="node3"

NODE_0_CLEAR="tendermint \
                --home "$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_0_NAME" \
                unsafe_reset_all"

NODE_0_APP_CLEAR="rm -rf $TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_0_NAME/appdata"

NODE_1_CLEAR="tendermint \
                --home "$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_1_NAME" \
                unsafe_reset_all"

NODE_1_APP_CLEAR="rm -rf $TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_1_NAME/appdata"

NODE_2_CLEAR="tendermint \
                --home "$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_2_NAME" \
                unsafe_reset_all"

NODE_2_APP_CLEAR="rm -rf $TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_2_NAME/appdata"

NODE_3_CLEAR="tendermint \
                --home "$TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_3_NAME" \
                unsafe_reset_all"

NODE_3_APP_CLEAR="rm -rf $TESTNET_ROOT_DIR/$TESTNET_FOLDER/$NODE_3_NAME/appdata"


$NODE_0_CLEAR
$NODE_0_APP_CLEAR
$NODE_1_CLEAR
$NODE_1_APP_CLEAR
$NODE_2_CLEAR
$NODE_2_APP_CLEAR
$NODE_3_CLEAR
$NODE_3_APP_CLEAR