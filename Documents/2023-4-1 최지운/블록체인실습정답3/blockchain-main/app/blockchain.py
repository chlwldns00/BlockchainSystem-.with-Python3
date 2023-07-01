import time
import hashlib
import json
from uuid import uuid4


class Blockchain:
    def __init__(self, current_node_url=None): #블록체인의 초기상태를 설정하고 제네시스 블록을 생성한다
        self.chain = []  # 블록들을 저장하는
        self.pending_transactions = [] # 블록에 추가되기 전 보류 중인 트랜잭션을 담는 리스트입니다.
        self.current_node_url = current_node_url # 
        self.network_nodes = [] #
        self.create_genesis_block()
        
        
    #새로운 블록을 생성하는 코드 + 체인에 추가
    def create_new_block(self, nonce, previous_block_hash, hash_, merkle_root): #
        new_block = {  
            'index': len(self.chain) + 1,
            'transactions': self.pending_transactions, #걍웬만하면 tx채우기는 pending_transaction
            'merkel_tree_process' : self.merkle_tree_proecss, # 머클트리 리스트
            'merkle_root': merkle_root,
            'nonce': nonce,
            'hash': hash_,
            'previous_block_hash': previous_block_hash
        }
        self.pending_transactions = []
        self.chain.append(new_block)
        return new_block
    #마지막 블록을 반환
    def get_last_block(self):
        return self.chain[len(self.chain) - 1]
    #트랜잭션 생성
    def create_new_transaction(self,amount,sender,recipient):
        new_transaction = {
            'amount' : amount,
            'sender' : sender,
            'recipient' : recipient,
            'transaction_id': str(uuid4()).replace('-', '')
        }
        return new_transaction
    #이전해시값,현재블록데이터,넌스값을 포함하는 블록의 해시값을 책정하는 함수
    def hash_block(self, previous_block_hash, current_block_data, nonce):
        data_as_string = previous_block_hash + str(nonce) + json.dumps(current_block_data, separators=(',', ':'))                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
        hash_object = hashlib.sha256(data_as_string.encode())
        hash_ = hash_object.hexdigest()
        return hash_
    #작업증명 블록의 해시값 맞추기(해시값에는 이전블록의 해시값,현재블록데이터,넌스값이 포함됩니다)
    def proof_of_work(self,previous_block_hash, current_block_data):
        nonce = 0
        hash_ = self.hash_block(previous_block_hash, current_block_data, nonce)
        while hash_[:4] != '0000':
            nonce += 1
            hash_ = self.hash_block(previous_block_hash, current_block_data, nonce)
            #print(hash_)
        return nonce
    #새로운 트랜잭션을 합의되지않아 보류중인 트랜잭션 리스트에 집어넣는 코드
    def add_transaction_to_pending_transactions(self,transaction_obj):
        self.pending_transactions.append(transaction_obj)
        return self.get_last_block()['index'] + 1
    #재네시스 블록에 트랜잭션을 추가하는 코드
    def add_genesis_transaction(self,transaction_obj):
        self.pending_transactions.append(transaction_obj)
        return True
    #체인에 있는 블록들을 돌면서 넌스값은 맞는지 이전해시값=현재 블록 해시값은 맞는지, 머클트리의 루트값은 맞는지 확인
    def chain_is_valid(self, chain):
        genesis_block = chain[0]
        correct_nonce = genesis_block['nonce'] == self.proof_of_work(self.hash_function('0'), {'merkle_root':genesis_block['merkle_root'],'index' : 1})
        correct_previous_block_hash = genesis_block['previous_block_hash'] == self.hash_function('0')
        correct_hash = genesis_block['hash'] == self.hash_block(self.hash_function('0'), {'merkle_root':genesis_block['merkle_root'],'index' : 1},genesis_block['nonce'])
        correct_transactions = len(genesis_block['transactions']) == 1
        validChain  = True

        if not (correct_nonce and correct_previous_block_hash and correct_hash and correct_transactions):
            validChain = False

        for i in range(1, len(chain)):
            current_block = chain[i]
            prev_block = chain[i - 1]

            block_hash = self.hash_block(prev_block['hash'],{"merkle_root": current_block['merkle_root'], "index": current_block['index']}, current_block['nonce'])
            print(block_hash)
            if block_hash[:4] != '0000': #nonce값이 틀리거나
                validChain = False

            if current_block['previousBlockHash'] != prev_block['hash']: #이전블록의 해시값과 현재 블록의 해시값이 틀리다면
                validChain = False

        return validChain
    #블록해시값으로 그 블록해시값에 맞는 블록을 반환한다
    def get_block(self, block_hash):
        correct_block = None
        for block in self.chain:
            if block['hash'] == block_hash:
                correct_block = block
                break
        return correct_block
    #트랜잭션 id값으로 트랜잭션을 찾는다
    def get_transaction(self, transaction_id):
        correct_transaction = None
        correct_block = None
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['transaction_id'] == transaction_id:
                    correct_transaction = transaction
                    correct_block = block
                    break
            if correct_transaction:
                break
        return {
            'transaction': correct_transaction,
            'block': correct_block
        }
    #주소에 맞는 트랜잭션값을 반환
    def get_address_data(self, address):
        address_transactions = []
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['sender'] == address or transaction['recipient'] == address:
                    address_transactions.append(transaction)

        balance = 0
        for transaction in address_transactions:
            if transaction['recipient'] == address:
                balance += transaction['amount']
            elif transaction['sender'] == address:
                balance -= transaction['amount']

        return {
            'addressTransactions': address_transactions,
            'addressBalance': balance
        }
    #해시값을 계산하는 함수
    def hash_function(self, data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    #머클트리의 노드값을 계산하는 함수
    def create_merkle_tree_node(self, left, right, index):
        self.merkle_tree_proecss.append(str(index) + ".left :" + left)
        self.merkle_tree_proecss.append(str(index) + ".right :" + right)
        self.merkle_tree_proecss.append(str(index) + ".result :" + self.hash_function(left + right))
        return self.hash_function(left + right)
    #머클 트리를 만드는 함수
    def create_merkle_tree(self, transactions):
        self.merkle_tree_proecss = []

        if len(transactions) == 0:
            print("1")
            return None


        elif len(transactions) == 1: # 제네시스 및 처음부터 한개일때
            transactions.append(transactions[-1]) #복제
            new_level = [] #
            index = 1
            for i in range(0, len(transactions), 2):
                left = transactions[i]
                right = transactions[i + 1]
                new_level.append(self.create_merkle_tree_node(left, right, index))
                index += 1
            
            transactions = new_level #복제한 tx로 만든 머클 트리 리스트

            return transactions[0] #루트노드가 되는 값
        
        else: #두개
            while len(transactions) > 1: #tx길이가 1이 될때까지
                index = 1

                if len(transactions) % 2 != 0: # 홀수일때는 마지막항목복제
                    transactions.append(transactions[-1])

                new_level = [] 
                for i in range(0, len(transactions), 2):
                    left = transactions[i]
                    right = transactions[i + 1]
                    new_level.append(self.create_merkle_tree_node(left, right, index))
                    index += 1

                transactions = new_level

            return transactions[0]
    #현재 노드의 주소를 생성하는 함수
    def node_address(self):
        node_address = str(uuid4()).replace('-', '')
        return node_address
    #제네시스 블록을 생성하는 함수(1.임의트랜잭션 추가, 2)
    def create_genesis_block(self):
        self.merkle_tree_proecss = []
        if len(self.chain) == 0:
            self.add_genesis_transaction({'amount' : 50,'sender': '0','recipient':'0','transaction_id' : str(uuid4()).replace('-','')})
            self.genesis_merkleroot = self.create_merkle_tree([self.hash_function(str(tx)) for tx in self.pending_transactions])
            self.genesis_nonce = self.proof_of_work(self.hash_function('0'), {'merkle_root':self.genesis_merkleroot,'index' : 1})
            self.create_new_block(self.genesis_nonce, self.hash_function('0'), self.hash_block(self.hash_function('0'), {'merkle_root':self.genesis_merkleroot,'index' : 1},self.genesis_nonce), self.genesis_merkleroot)
        if(len(self.chain) == 1):
            self.pending_transactions.append(self.create_new_transaction(6.25,'00',"00"))
    