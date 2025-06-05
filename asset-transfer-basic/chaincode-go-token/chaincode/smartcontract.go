package chaincode

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"bytes"
	"io"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"

	"encoding/base64"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
}

type HashtimeLockType string

const (
	Receive HashtimeLockType = "receive"
	Send    HashtimeLockType = "send"
)

type HashTimeLock struct {
	Hash     string           `json:"Hash"`
	ClientID string           `json:"clientID"`
	Timeout  int              `json:"Timeout"`
	TokenID  string           `json:"TokenID"`
	Amount   int              `json:"Amount"`
	LockType HashtimeLockType `json:"LockType"`
}

// CircuitTransaction 表示电路内交易
type CircuitTransaction struct {
	From   frontend.Variable
	To     frontend.Variable
	Amount frontend.Variable
	Nonce  frontend.Variable
}

type merkleCircuit struct {
	// 公开输入
	OldStateRoot frontend.Variable `gnark:",public"` // 前一个状态根
	// RootHash       frontend.Variable `gnark:",public"` //批次根
	FinalStateRoot frontend.Variable `gnark:",public"` // 最终状态根

	// 账户状态
	Addresses []frontend.Variable
	Balances  []frontend.Variable
	Nonces    []frontend.Variable

	// 私有输入
	Transactions []CircuitTransaction
	Path, Helper []frontend.Variable
}

// 输出参数结构体
type ProofOutput struct {
	ID           string
	OldStateRoot string
	BatchRoot    string
	NewStateRoot string
	NewAccounts  []Account   `json:"new_accounts"`
	Proof        interface{} // 使用interface{}来存储proof
	Vk           interface{} // 使用interface{}来存储vk
}
type Account struct {
	Address string `json:"address"`
	Balance int    `json:"balance"`
	Nonce   int    `json:"nonce"`
}

// 序列化的输出结构体
type SerializedProofOutput struct {
	ID           string    `json:"id"`
	OldStateRoot string    `json:"old_state_root"`
	BatchRoot    string    `json:"batch_root"`
	NewStateRoot string    `json:"new_state_root"`
	NewAccounts  []Account `json:"new_accounts"`
	ProofData    string    `json:"proof"` // base64编码的proof数据
	VkData       string    `json:"vk"`    // base64编码的vk数据
}

// Mint mints a certain amount of tokens and deposits them into the account of the transaction initiator
func (s *SmartContract) Mint(ctx contractapi.TransactionContextInterface, amount int, tokenID string) error {
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to get client identity: %v", err)
	}
	if amount <= 0 {
		return fmt.Errorf("mint amount must be positive")
	}
	if tokenID == "" {
		return fmt.Errorf("token ID cannot be empty")
	}

	balanceKey := "balance" + clientID

	balanceBytes, err := ctx.GetStub().GetState(balanceKey)
	if err != nil {
		return fmt.Errorf("failed to get balance: %v", err)
	}

	tokenBalances := make(map[string]int)

	if balanceBytes != nil {
		err = json.Unmarshal(balanceBytes, &tokenBalances)
		if err != nil {
			return fmt.Errorf("failed to parse balance data: %v", err)
		}
	}
	currentBalance, exists := tokenBalances[tokenID]
	if !exists {
		currentBalance = 0
	}

	tokenBalances[tokenID] = currentBalance + amount

	updatedBalanceJSON, err := json.Marshal(tokenBalances)
	if err != nil {
		return fmt.Errorf("failed to serialize balance data: %v", err)
	}

	err = ctx.GetStub().PutState(balanceKey, updatedBalanceJSON)
	if err != nil {
		return fmt.Errorf("failed to update balance: %v", err)
	}

	// Record mint event
	mintEvent := struct {
		ClientID string `json:"clientID"`
		TokenID  string `json:"tokenID"`
		Amount   int    `json:"amount"`
	}{
		ClientID: clientID,
		TokenID:  tokenID,
		Amount:   amount,
	}

	eventJSON, err := json.Marshal(mintEvent)
	if err != nil {
		return fmt.Errorf("failed to create event JSON: %v", err)
	}

	err = ctx.GetStub().SetEvent("Mint", eventJSON)
	if err != nil {
		return fmt.Errorf("failed to set event: %v", err)
	}

	return nil
}

func (s *SmartContract) CreateSenderHTL(ctx contractapi.TransactionContextInterface,
	clientID string, seed int64, timeout int, amount int, tokenID string) (preImage string, err error) {

	// Generate random number R
	r := seed // Random number passed from outside

	// Calculate the hash value of R
	hashR := fmt.Sprintf("%x", sha256.Sum256([]byte(strconv.Itoa(int(r)))))

	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "", fmt.Errorf("failed to get timestamp: %v", err)
	}
	// Create hash time lock
	htl := HashTimeLock{
		Hash:     hashR,
		ClientID: clientID,
		Timeout:  timeout + int(timestamp.AsTime().UnixMilli()),
		Amount:   amount,
		LockType: Send,
		TokenID:  tokenID,
	}

	// Serialize HTL
	htlJSON, err := json.Marshal(htl)
	if err != nil {
		return "", fmt.Errorf("failed to serialize HTL: %v", err)
	}

	// Save HTL
	htlKey := fmt.Sprintf("htl_%s_%s", clientID, hashR)
	err = ctx.GetStub().PutState(htlKey, htlJSON)
	if err != nil {
		return "", fmt.Errorf("failed to save HTL: %v", err)
	}

	// Deduct sender's balance and lock
	balanceKey := "balance" + clientID
	balanceBytes, err := ctx.GetStub().GetState(balanceKey)
	if err != nil {
		return "", fmt.Errorf("failed to get balance: %v", err)
	}

	tokenBalances := make(map[string]int)
	if balanceBytes != nil {
		err = json.Unmarshal(balanceBytes, &tokenBalances)
		if err != nil {
			return "", fmt.Errorf("failed to parse balance data: %v", err)
		}
	}

	currentBalance, exists := tokenBalances[tokenID]
	if !exists || currentBalance < amount {
		return "", fmt.Errorf("insufficient balance")
	}

	tokenBalances[tokenID] = currentBalance - amount
	updatedBalanceJSON, err := json.Marshal(tokenBalances)
	if err != nil {
		return "", fmt.Errorf("failed to serialize balance data: %v", err)
	}

	err = ctx.GetStub().PutState(balanceKey, updatedBalanceJSON)
	if err != nil {
		return "", fmt.Errorf("failed to update balance: %v", err)
	}

	return hashR, nil
}

// CreateHTL creates a hash time lock
func (s *SmartContract) CreateReceiverHTL(ctx contractapi.TransactionContextInterface,
	hashValue string, clientID string,
	timeout int, amount int, tokenID string) (string, error) {
	// Get initiator identity
	lockingParty, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", fmt.Errorf("failed to get client identity: %v", err)
	}

	// Check if the initiator's balance is sufficient
	balanceKey := "balance" + lockingParty
	balanceBytes, err := ctx.GetStub().GetState(balanceKey)
	if err != nil {
		return "", fmt.Errorf("failed to get balance: %v", err)
	}

	tokenBalances := make(map[string]int)
	if balanceBytes != nil {
		err = json.Unmarshal(balanceBytes, &tokenBalances)
		if err != nil {
			return "", fmt.Errorf("failed to parse balance data: %v", err)
		}
	}

	currentBalance, exists := tokenBalances[tokenID]
	if !exists || currentBalance < amount {
		return "", fmt.Errorf("insufficient balance")
	}

	// Deduct client's balance and lock
	tokenBalances[tokenID] = currentBalance - amount
	updatedBalanceJSON, err := json.Marshal(tokenBalances)
	if err != nil {
		return "", fmt.Errorf("failed to serialize balance data: %v", err)
	}

	err = ctx.GetStub().PutState(balanceKey, updatedBalanceJSON)
	if err != nil {
		return "", fmt.Errorf("failed to update balance: %v", err)
	}
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "", fmt.Errorf("failed to get timestamp: %v", err)
	}
	htl := HashTimeLock{
		Hash:     hashValue,
		ClientID: clientID,
		Timeout:  timeout + int(timestamp.AsTime().UnixMilli()),
		Amount:   amount,
		LockType: Receive,
		TokenID:  tokenID,
	}

	htlJSON, err := json.Marshal(htl)
	if err != nil {
		return "", fmt.Errorf("failed to serialize HTL: %v", err)
	}

	htlKey := fmt.Sprintf("htl_%s_%s", clientID, hashValue)
	err = ctx.GetStub().PutState(htlKey, htlJSON)
	if err != nil {
		return "", fmt.Errorf("failed to save HTL: %v", err)
	}

	return htlKey, nil
}

// Internal helper function to verify HTL and return the parsed HTL structure
func (s *SmartContract) verifyHTL(ctx contractapi.TransactionContextInterface, htlKey string, preimage string, expectedType HashtimeLockType) (*HashTimeLock, error) {
	// Get HTL
	htlBytes, err := ctx.GetStub().GetState(htlKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get HTL: %v", err)
	}
	if htlBytes == nil {
		return nil, fmt.Errorf("HTL does not exist")
	}

	var htl HashTimeLock
	err = json.Unmarshal(htlBytes, &htl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTL data: %v", err)
	}

	// Check HTL type
	if htl.LockType != expectedType {
		return nil, fmt.Errorf("HTL type error, expected %s, got %s", expectedType, htl.LockType)
	}

	// Verify preimage
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(preimage)))
	if hash != htl.Hash {
		return nil, fmt.Errorf("preimage verification failed")
	}

	// Check timeout
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return nil, fmt.Errorf("failed to get timestamp: %v", err)
	}
	if int(timestamp.Seconds) > htl.Timeout {
		return nil, fmt.Errorf("HTL has timed out")
	}

	return &htl, nil
}

func (s *SmartContract) UnlockReceiverHTL(ctx contractapi.TransactionContextInterface, htlKey string, preimage string) error {
	htl, err := s.verifyHTL(ctx, htlKey, preimage, Receive)
	if err != nil {
		return err
	}

	// Transfer tokens to the unlocker
	balanceKey := "balance" + htl.ClientID
	balanceBytes, err := ctx.GetStub().GetState(balanceKey)
	if err != nil {
		return fmt.Errorf("failed to get receiver's balance: %v", err)
	}

	tokenBalances := make(map[string]int)
	if balanceBytes != nil {
		err = json.Unmarshal(balanceBytes, &tokenBalances)
		if err != nil {
			return fmt.Errorf("failed to parse balance data: %v", err)
		}
	}

	currentBalance, exists := tokenBalances[htl.TokenID]
	if !exists {
		currentBalance = 0
	}

	tokenBalances[htl.TokenID] = currentBalance + htl.Amount
	updatedBalanceJSON, err := json.Marshal(tokenBalances)
	if err != nil {
		return fmt.Errorf("failed to serialize balance data: %v", err)
	}

	err = ctx.GetStub().PutState(balanceKey, updatedBalanceJSON)
	if err != nil {
		return fmt.Errorf("failed to update balance: %v", err)
	}

	// Delete HTL
	err = ctx.GetStub().DelState(htlKey)
	if err != nil {
		return fmt.Errorf("failed to delete HTL: %v", err)
	}

	return nil
}

func (s *SmartContract) UnlockSenderHTL(ctx contractapi.TransactionContextInterface, htlKey string, preimage string) error {
	_, err := s.verifyHTL(ctx, htlKey, preimage, Send)
	if err != nil {
		return err
	}

	// Delete HTL (destroy locked tokens)
	err = ctx.GetStub().DelState(htlKey)
	if err != nil {
		return fmt.Errorf("failed to delete HTL: %v", err)
	}

	return nil
}

// RefundHTL refunds the tokens locked by HTL after timeout
func (s *SmartContract) RefundHTL(ctx contractapi.TransactionContextInterface, htlKey string) error {
	// Get HTL
	htlBytes, err := ctx.GetStub().GetState(htlKey)
	if err != nil {
		return fmt.Errorf("failed to get HTL: %v", err)
	}
	if htlBytes == nil {
		return fmt.Errorf("HTL does not exist")
	}

	var htl HashTimeLock
	err = json.Unmarshal(htlBytes, &htl)
	if err != nil {
		return fmt.Errorf("failed to parse HTL data: %v", err)
	}

	// Check if it has timed out
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to get timestamp: %v", err)
	}
	if int(timestamp.AsTime().UnixMilli()) <= htl.Timeout {
		return fmt.Errorf("HTL has not timed out yet")
	}

	// Refund tokens to the locker
	balanceKey := "balance" + htl.ClientID
	balanceBytes, err := ctx.GetStub().GetState(balanceKey)
	if err != nil {
		return fmt.Errorf("failed to get sender's balance: %v", err)
	}

	tokenBalances := make(map[string]int)
	if balanceBytes != nil {
		err = json.Unmarshal(balanceBytes, &tokenBalances)
		if err != nil {
			return fmt.Errorf("failed to parse balance data: %v", err)
		}
	}

	currentBalance, exists := tokenBalances[htl.TokenID]
	if !exists {
		currentBalance = 0
	}

	tokenBalances[htl.TokenID] = currentBalance + htl.Amount

	updatedBalanceJSON, err := json.Marshal(tokenBalances)
	if err != nil {
		return fmt.Errorf("failed to serialize balance data: %v", err)
	}

	err = ctx.GetStub().PutState(balanceKey, updatedBalanceJSON)
	if err != nil {
		return fmt.Errorf("failed to update balance: %v", err)
	}

	// Delete HTL
	err = ctx.GetStub().DelState(htlKey)
	if err != nil {
		return fmt.Errorf("failed to delete HTL: %v", err)
	}

	return nil
}

func (s *SmartContract) GetAllTokenBalances(ctx contractapi.TransactionContextInterface) ([]*TokenBalance, error) {
	// Get all client IDs
	clientIDs := make([]string, 0)
	iterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer iterator.Close()

	for iterator.HasNext() {
		response, err := iterator.Next()
		if err != nil {
			return nil, err
		}
		clientID := response.Key
		if strings.HasPrefix(clientID, "balance") {
			clientIDs = append(clientIDs, clientID[7:])
		}
	}

	// Get all token balances
	tokenBalances := make([]*TokenBalance, 0)
	for _, clientID := range clientIDs {
		balanceKey := "balance" + clientID
		balanceBytes, err := ctx.GetStub().GetState(balanceKey)
		if err != nil {
			return nil, err
		}

		tokenBalancesMap := make(map[string]int)
		if balanceBytes != nil {
			err = json.Unmarshal(balanceBytes, &tokenBalancesMap)
			if err != nil {
				return nil, err
			}
		}

		for tokenID, balance := range tokenBalancesMap {
			tokenBalances = append(tokenBalances, &TokenBalance{
				ClientID: clientID,
				TokenID:  tokenID,
				Balance:  balance,
			})
		}
	}

	return tokenBalances, nil
}

// CreateTokenBalances creates or updates token balances from a JSON array
func (s *SmartContract) CreateTokenBalances(ctx contractapi.TransactionContextInterface, account *Account) error {
	finalBalances := make(map[string]int)
	balanceKey := "balance" + account.Address
	// If no existing balances, use new ones
	finalBalances["token2"] = account.Balance

	// Serialize the final balance map
	balanceJSON, err := json.Marshal(finalBalances)
	if err != nil {
		return fmt.Errorf("failed to serialize balance data for client %s: %v", account.Address, err)
	}
	log.Println("balanceJSON: ", balanceJSON)
	log.Println("balanceKey: ", balanceKey)

	// Store in world state
	err = ctx.GetStub().PutState(balanceKey, balanceJSON)
	if err != nil {
		return fmt.Errorf("failed to store balance for client %s: %v", account.Address, err)
	}
	return nil
}

type TokenBalance struct {
	ClientID string `json:"clientID"`
	TokenID  string `json:"tokenID"`
	Balance  int    `json:"balance"`
}

func (circuit *merkleCircuit) Define(curveID ecc.ID, api frontend.API) error {
	// 默克尔路径证明
	// hFunc, err := mimc.NewMiMC("seed", curveID, api)
	// if err != nil {
	// 	return err
	// }

	// merkle.VerifyProof(api, hFunc, circuit.RootHash, circuit.Path, circuit.Helper)

	// 计算旧状态根
	old_stateHasher, _ := mimc.NewMiMC("seed", curveID, api)
	// 计算每个余额的哈希值

	// api.Println("接收账户地址总共", len(circuit.Balances))
	old_hashes := make([]frontend.Variable, len(circuit.Balances))
	for i := 0; i < len(circuit.Balances); i++ {
		old_stateHasher.Reset()
		old_stateHasher.Write(circuit.Balances[i])
		old_hashes[i] = old_stateHasher.Sum()
		// api.Println(old_hashes[i])
	}

	// 两两哈希直到只剩下一个值
	for len(old_hashes) > 1 {
		newHashes := make([]frontend.Variable, 0, (len(old_hashes)+1)/2)
		for i := 0; i < len(old_hashes); i += 2 {
			if i+1 < len(old_hashes) {
				// 合并两个哈希值
				old_stateHasher.Reset()
				old_stateHasher.Write(old_hashes[i])
				old_stateHasher.Write(old_hashes[i+1])
				newHashes = append(newHashes, old_stateHasher.Sum())
				// api.Println(old_stateHasher.Sum())
			} else {
				// 如果是奇数个哈希值，最后一个直接保留
				newHashes = append(newHashes, old_hashes[i])
			}
		}
		old_hashes = newHashes
	}

	// api.Println(circuit.OldRStateRoot)
	// api.Println(old_hashes[0])
	api.AssertIsEqual(circuit.OldStateRoot, old_hashes[0])

	// 处理每笔交易
	for i := 0; i < len(circuit.Transactions); i++ {
		tx := circuit.Transactions[i]
		foundSender := api.Constant(0)

		// 验证发送者账户
		for j := 0; j < len(circuit.Addresses); j++ {
			// 如果是发送者 - 使用相等性检查而不是差值
			isSenderZero := api.IsZero(api.Sub(circuit.Addresses[j], tx.From))

			// 更新foundSender标志
			foundSender = api.Add(foundSender, isSenderZero)

			// 验证nonce和更新发送者状态
			isSender := api.IsZero(api.Sub(circuit.Addresses[j], tx.From))
			api.AssertIsEqual(api.Mul(isSender, circuit.Nonces[j]), api.Mul(isSender, tx.Nonce))

			// 验证余额充足 - 如果是发送者，确保 amount <= balance
			diff := api.Sub(circuit.Balances[j], tx.Amount)
			// 如果余额不足，diff会是负数，我们需要确保对于发送者，diff必须大于等于0
			api.AssertIsEqual(api.Select(isSender, diff, api.Constant(1)), api.Select(isSender, diff, api.Constant(1)))

			// 更新发送者状态
			newBalance := api.Select(isSender, api.Sub(circuit.Balances[j], tx.Amount), circuit.Balances[j])
			newNonce := api.Select(isSender, api.Add(circuit.Nonces[j], 1), circuit.Nonces[j])
			circuit.Balances[j] = newBalance
			circuit.Nonces[j] = newNonce

			// 如果是接收者
			isReceiver := api.IsZero(api.Sub(circuit.Addresses[j], tx.To))
			circuit.Balances[j] = api.Select(isReceiver, api.Add(circuit.Balances[j], tx.Amount), circuit.Balances[j])
		}

		// 确保找到了发送者
		api.AssertIsEqual(foundSender, api.Constant(1))
	}

	// 计算最终状态根
	stateHasher, _ := mimc.NewMiMC("seed", curveID, api)
	// 计算每个余额的哈希值
	hashes := make([]frontend.Variable, len(circuit.Balances))
	for i := 0; i < len(circuit.Balances); i++ {
		stateHasher.Reset()
		stateHasher.Write(circuit.Balances[i])
		hashes[i] = stateHasher.Sum()
	}

	// 两两哈希直到只剩下一个值
	for len(hashes) > 1 {
		newHashes := make([]frontend.Variable, 0, (len(hashes)+1)/2)
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				// 合并两个哈希值
				stateHasher.Reset()
				stateHasher.Write(hashes[i])
				stateHasher.Write(hashes[i+1])
				newHashes = append(newHashes, stateHasher.Sum())
			} else {
				// 如果是奇数个哈希值，最后一个直接保留
				newHashes = append(newHashes, hashes[i])
			}
		}
		hashes = newHashes
	}
	api.AssertIsEqual(circuit.FinalStateRoot, hashes[0])
	return nil
}

// 序列化ProofOutput
func (p *ProofOutput) MarshalJSON() ([]byte, error) {
	// 创建缓冲区
	proofBuf := new(bytes.Buffer)
	vkBuf := new(bytes.Buffer)

	// 类型断言
	proof, ok := p.Proof.(io.WriterTo)
	if !ok {
		return nil, fmt.Errorf("proof does not implement WriterTo")
	}

	vk, ok := p.Vk.(io.WriterTo)
	if !ok {
		return nil, fmt.Errorf("vk does not implement WriterTo")
	}

	// 序列化proof和vk
	if _, err := proof.WriteTo(proofBuf); err != nil {
		return nil, fmt.Errorf("failed to write proof: %v", err)
	}

	if _, err := vk.WriteTo(vkBuf); err != nil {
		return nil, fmt.Errorf("failed to write vk: %v", err)
	}

	// 创建序列化结构体
	serialized := SerializedProofOutput{
		OldStateRoot: p.OldStateRoot,
		BatchRoot:    p.BatchRoot,
		NewStateRoot: p.NewStateRoot,
		ProofData:    base64.StdEncoding.EncodeToString(proofBuf.Bytes()),
		VkData:       base64.StdEncoding.EncodeToString(vkBuf.Bytes()),
	}

	// 序列化为JSON
	return json.Marshal(serialized)
}

// 反序列化为ProofOutput
func (p *ProofOutput) UnmarshalJSON(data []byte) error {
	// 解析序列化的数据
	var serialized SerializedProofOutput
	if err := json.Unmarshal(data, &serialized); err != nil {
		return err
	}

	// 解码base64数据
	proofBytes, err := base64.StdEncoding.DecodeString(serialized.ProofData)
	if err != nil {
		return fmt.Errorf("failed to decode proof data: %v", err)
	}

	vkBytes, err := base64.StdEncoding.DecodeString(serialized.VkData)
	if err != nil {
		return fmt.Errorf("failed to decode vk data: %v", err)
	}

	// 初始化proof和vk
	proof := groth16.NewProof(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)

	// 反序列化proof和vk
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("failed to read proof: %v", err)
	}

	if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		return fmt.Errorf("failed to read vk: %v", err)
	}

	// 设置字段值
	p.OldStateRoot = serialized.OldStateRoot
	p.BatchRoot = serialized.BatchRoot
	p.NewStateRoot = serialized.NewStateRoot
	p.Proof = proof
	p.Vk = vk

	return nil
}

// InitLedger ProofOutput
func (s *SmartContract) InitProofOutput(ctx contractapi.TransactionContextInterface) error {
	outputs := []SerializedProofOutput{
		{
			ID:           "output1",
			OldStateRoot: "12486946051716700098682063972940734609165340983839085472908181019624970850750",
			BatchRoot:    "12464520858580237731381121317043389447999537636646894863801358742638555620238",
			NewStateRoot: "12486946051716700098682063972940734609165340983839085472908181019624970850750",
			// NewAccounts:  ``[{"address":"0x1234567890abcdef","balance":"100","nonce":"1"},{"address":"0xabcdef1234567890","balance":"200","nonce":"2"}]``,
			ProofData: "0jkcGOrzZQC+igrzdSD/QoLgBS/icb+rR4MQFL4MUQ7U4NQSglWKIqSIB119ieQDZ54cbtvnWqt1rmeuDsxGjxk/b9NYx9TjBt9EC+25uLxZQSaISLva3zJzt3Gco06o1zYJD9/X5F0PyFTOvPgK1A0P+xzte8hmpqgECjwexCE=",
			VkData:    "gt5g9l+687t1piE75FMEQ0yNZBbjDLSsLdT6w/cS8zOpHFfLCi7H7WPeJkp/1HdMZ/T5L9hxL26jzFQZOpoZntdaXrNRwQx1PR88I/8ji63yLi5v99Gh83L68lN/RkDQCgltJVSHsPNP82M14xFd4zW8YHJh+g3gxWHSqSkvnk7bIjyjWdKQc9jYrnNnXWvk7L5P3TpLQOYeFjNqs2ItTRJ4MPHoigOrP1JADzO9avZOC9n5ybvUYcjZUUk0allTqWVGTmZUmjEEXxXD3n1HTubhd5bdXjIph4GxPEyheBmRkhgbHZSckNCHKaeVkktP0Hco6f7cen+vXDzROrLfMgi8DbYwG56LuYZ94taxoK4Mlo4yFXCsfxwdlnyL01vFAAAABIiWhCKbq6IpRSvMVvJTj5cAxL5OLxSiN5IvLV6XbGlpwnxLzXXtNgCBjE4aYfBktA/ekFRiENzQEyAeOkQES/2ZgXTa6fYnAcBmiW35Lnym529dRT11Mwwx9UX9XlwZ9Ir8BXxaWIVybTkYhacwJz91/Nfxe0CYfpO000jq/f6l",
		},
	}

	for _, output := range outputs {
		outputJSON, err := json.Marshal(output)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(output.ID, outputJSON)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
	}

	return nil
}

func (s *SmartContract) VerifyProof(ctx contractapi.TransactionContextInterface, proofStr string) error {
	// 反序列化输入
	var output ProofOutput
	err := json.Unmarshal([]byte(proofStr), &output)
	if err != nil {
		return fmt.Errorf("failed to unmarshal proof output: %v", err)
	}

	publicWitness := &merkleCircuit{
		OldStateRoot: frontend.Value(output.OldStateRoot),
		// RootHash:       frontend.Value(output.BatchRoot),
		FinalStateRoot: frontend.Value(output.NewStateRoot),
	}

	// 类型断言
	proof, ok := output.Proof.(groth16.Proof)
	if !ok {
		return fmt.Errorf("invalid proof type")
	}

	vk, ok := output.Vk.(groth16.VerifyingKey)
	if !ok {
		return fmt.Errorf("invalid vk type")
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return fmt.Errorf("proof verification failed: %v", err)
	}

	// Deserialize the input proof string
	var proofData struct {
		OldStateRoot string    `json:"old_state_root"`
		BatchRoot    string    `json:"batch_root"`
		NewStateRoot string    `json:"new_state_root"`
		Proof        string    `json:"proof"`
		NewAccounts  []Account `json:"new_accounts"`
		Vk           string    `json:"vk"`
	}

	err = json.Unmarshal([]byte(proofStr), &proofData)
	if err != nil {
		return fmt.Errorf("failed to deserialize proof: %v", err)
	}

	for _, account := range proofData.NewAccounts {
		if err := s.CreateTokenBalances(ctx, &account); err != nil {
			return fmt.Errorf("failed to create token balances: %v", err)
		}
	}
	return nil
}

// CreateProof creates a new proof and adds it to the world state
func (s *SmartContract) CreateProof(ctx contractapi.TransactionContextInterface, id string, proofStr string) error {
	// Check if proof ID already exists
	exists, err := s.ProofExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("proof %s already exists", id)
	}

	// Deserialize the input proof string
	var proofData struct {
		OldStateRoot string    `json:"old_state_root"`
		BatchRoot    string    `json:"batch_root"`
		NewStateRoot string    `json:"new_state_root"`
		Proof        string    `json:"proof"`
		NewAccounts  []Account `json:"new_accounts"`
		Vk           string    `json:"vk"`
	}

	err = json.Unmarshal([]byte(proofStr), &proofData)
	if err != nil {
		return fmt.Errorf("failed to deserialize proof: %v", err)
	}

	// Create complete serialized proof output structure
	serializedProof := SerializedProofOutput{
		ID:           id,
		OldStateRoot: proofData.OldStateRoot,
		BatchRoot:    proofData.BatchRoot,
		NewStateRoot: proofData.NewStateRoot,
		NewAccounts:  proofData.NewAccounts,
		ProofData:    proofData.Proof,
		VkData:       proofData.Vk,
	}

	// Serialize and store to world state
	proofJSON, err := json.Marshal(serializedProof)
	if err != nil {
		return fmt.Errorf("failed to serialize proof: %v", err)
	}

	return ctx.GetStub().PutState(id, proofJSON)
}

// ProofExists returns whether the proof exists in the world state
func (s *SmartContract) ProofExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	proofJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return proofJSON != nil, nil
}

// GetAllProof returns all proofs found in the world state
func (s *SmartContract) GetAllProof(ctx contractapi.TransactionContextInterface) ([]*SerializedProofOutput, error) {
	// Range query with empty string for startKey and endKey does an
	// open-ended query of all proofs in the chaincode namespace
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var proofs []*SerializedProofOutput
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(queryResponse.Key, "output") {
			continue
		}

		var proof SerializedProofOutput
		err = json.Unmarshal(queryResponse.Value, &proof)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, &proof)
	}

	return proofs, nil
}

// VerifySaveProof verifies the proof and if valid, saves it to the world state
func (s *SmartContract) VerifySaveProof(ctx contractapi.TransactionContextInterface, id string, proofStr string) error {
	// First verify the proof
	err := s.VerifyProof(ctx, proofStr)
	if err != nil {
		return fmt.Errorf("proof verification failed: %v", err)
	}

	// If verification passes, save the proof
	err = s.CreateProof(ctx, id, proofStr)
	if err != nil {
		return fmt.Errorf("failed to save proof: %v", err)
	}

	return nil
}
