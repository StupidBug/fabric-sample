env="test"

while getopts 'c:' option; do
    case "$option" in
        c)
            env=$OPTARG
            ;;
    esac
done

cd test-network

./network.sh down
./network.sh up createChannel -c mychannel -ca
./network.sh deployCC -ccn basic -ccp ../asset-transfer-basic/chaincode-go-${env}/ -ccl go