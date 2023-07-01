from flask import Flask, request, jsonify, render_template, send_from_directory

from blockchain import Blockchain
from uuid import uuid4
import requests
import sys

app = Flask(__name__)
bitcoin = Blockchain()

node_address = str(uuid4()).replace('-', '')
#전체 블록의 데이터(체인(블록정보)+미결트랜잭션+현재 노드+참여하고있는 노드의 네트워크)
@app.route('/blockchain', methods=['GET']) #전체 블록을 보여줌
def get_blockchain():
    blockchain_data = bitcoin.__dict__.copy() 

    blockchain_data.pop('genesis_merkleroot', None)
    blockchain_data.pop('genesis_nonce', None)
    blockchain_data.pop('merkle_tree_process', None)

    response = {
        'chain': blockchain_data['chain'],
        'pending_transactions': blockchain_data['pending_transactions'],
        'current_node_url' : blockchain_data['current_node_url'],
        'network_nodes' : blockchain_data['network_nodes']
    }
    return jsonify(response), 200

#현재 등록된 검증받은 tx들을 json데이터로 출력한다. 현재(새롭게 들어온)거래는 미결 tx로 설정한다.
@app.route('/transaction', methods=['POST']) # pending_transactions에 transaction 추가
def create_transaction():
    new_transaction = request.get_json()
    block_index = bitcoin.add_transaction_to_pending_transactions(new_transaction)
    return jsonify({'note': f'Transaction will be added in block {block_index}.'})




@app.route('/mine', methods=['GET']) # 작업증명
def mine():
    last_block = bitcoin.get_last_block()
    previous_block_hash = last_block['hash']
    merkle_root = bitcoin.create_merkle_tree([bitcoin.hash_function(str(tx)) for tx in bitcoin.pending_transactions]) #미결거래들을 모아서 머클루트값 뽑아내기
    current_block_data = { #마이닝할 블록데이터에대한 정보
        'merkle_root': merkle_root,
        'index': last_block['index'] + 1
    }
    bitcoin.create_new_transaction(6.25, "00", node_address)  #마이닝할 블록에 대해 새로운 tx를 추가하고 pow 로 논스값 맞추기를 통해 블록을 마이닝 + 블록의 해시데이터 설정 + 그리고 앞서 설정한값들로 새블록생성(마이닝)
    nonce = bitcoin.proof_of_work(previous_block_hash, current_block_data)
    block_hash = bitcoin.hash_block(previous_block_hash, current_block_data, nonce)
    new_block = bitcoin.create_new_block(nonce, previous_block_hash, block_hash, merkle_root)

    request_promises = []

    for network_node_url in bitcoin.network_nodes:
        request_options = {
            'newBlock': new_block
        }
        res = requests.post(network_node_url + '/receive-new-block', json=request_options) #노드를 돌면서 블록정보를 전달 (검증과정)
        request_promises.append(res)

    responses = [rp.json() for rp in request_promises]

    request_options = {
        'amount': 6.25,
        'sender': "00",
        'recipient': node_address
    }
    requests.post(bitcoin.current_node_url + '/transaction/broadcast', json=request_options) #거래를 브로드 캐스트 합니다

    return jsonify({
        'note': "New block mined successfully",   #블록을 성공적으로 마이닝
        'block': new_block
    })
#새로운 노드가 참여할때, 기존 네트워크를 형성하던 노드들을 돌면서 뉴노드 url을 추가 후(register-node), register-node-bulk를 이용해 이 노드들을 하나의 변수에 저장
@app.route('/register-and-broadcast-node', methods=['POST'])
def register_and_broadcast_node():
    new_node_url = request.json['newNodeUrl']
    if new_node_url not in bitcoin.network_nodes:
        bitcoin.network_nodes.append(new_node_url)

    reg_nodes_promises = []
    for network_node_url in bitcoin.network_nodes:
        response = requests.post(f"{network_node_url}/register-node", json={'newNodeUrl': new_node_url})
        reg_nodes_promises.append(response)

    for response in reg_nodes_promises:
        if response.status_code == 200:
            requests.post(f"{new_node_url}/register-nodes-bulk", json={'allNetworkNodes': bitcoin.network_nodes + [bitcoin.current_node_url]})

    return jsonify({'note': 'New node registered with network successfully.'})

#현재 노드 네트워크에 참여하고 있지 않은 새로운 노드를 등록
@app.route('/register-node', methods=['POST'])
def register_node():
    new_node_url = request.json['newNodeUrl']
    node_not_already_present = new_node_url not in bitcoin.network_nodes
    not_current_node = bitcoin.current_node_url != new_node_url
    if node_not_already_present and not_current_node:
        bitcoin.network_nodes.append(new_node_url)
    return jsonify({'note': 'New node registered successfully.'})

#노드 네트워크 모두를 합쳐서 대량의 노드를 한꺼번에 등록할수있는 기능
@app.route('/register-nodes-bulk', methods=['POST'])
def register_nodes_bulk():
    all_network_nodes = request.json['allNetworkNodes']
    for network_node_url in all_network_nodes:
        node_not_already_present = network_node_url not in bitcoin.network_nodes
        not_current_node = bitcoin.current_node_url != network_node_url
        if node_not_already_present and not_current_node:
            bitcoin.network_nodes.append(network_node_url)

    return jsonify({'note': 'Bulk registration successful.'}) 
#트랜잭션 생성후 다른 노드에 게시
@app.route('/transaction/broadcast', methods=['POST'])
def broadcast_transaction():
    new_transaction = bitcoin.create_new_transaction(
        request.json['amount'],
        request.json['sender'],
        request.json['recipient']
    )
    bitcoin.add_transaction_to_pending_transactions(new_transaction)

    request_promises = []
    for network_node_url in bitcoin.network_nodes:
        request_options = {
            'url': network_node_url + '/transaction',
            'json': new_transaction
        }
        request_promises.append(requests.post(**request_options))

    for response in request_promises:
        response.raise_for_status()

    return jsonify({'note': 'Transaction created and broadcast successfully.'})
#블록체인 노드 네트워크에 새로운 블록을 받아들이고 검증하는 api
@app.route('/receive-new-block', methods=['POST'])
def receive_new_block():
    new_block = request.json['newBlock']
    last_block = bitcoin.get_last_block()
    correct_hash = last_block['hash'] == new_block['previous_block_hash']
    correct_index = last_block['index'] + 1 == new_block['index']
    print(correct_hash)
    print(correct_index)
    if correct_hash and correct_index:
        bitcoin.chain.append(new_block)
        bitcoin.pending_transactions = []
        return jsonify({
            'note': 'New block received and accepted',
            'newBlock': new_block
        })
    else:
        return jsonify({
            'note': 'New block rejected.',
            'newBlock': new_block
        })
#가장 긴 체인으로 블록체인을 갱신하기 위한 api
@app.route('/consensus', methods=['GET'])
def consensus():
    request_promises = []
    for network_node_url in bitcoin.network_nodes:
        request_promises.append(requests.get(network_node_url + '/blockchain'))

    blockchains = [rp.json() for rp in request_promises]
    current_chain_length = len(bitcoin.chain)
    max_chain_length = current_chain_length
    new_longest_chain = None
    new_pending_transactions = None

    for blockchain in blockchains:
        if len(blockchain['chain']) > max_chain_length:
            max_chain_length = len(blockchain['chain'])
            new_longest_chain = blockchain['chain']
            new_pending_transactions = blockchain['pending_transactions']

    if new_longest_chain == None or (new_longest_chain and not bitcoin.chain_is_valid(new_longest_chain)):
        return jsonify({
            'note': 'Current chain has not been replaced.',
            'chain': bitcoin.chain
        }) #가장긴 체인이 없거나, 체인이 유효하지 않은경우 갱신x

    else:
        bitcoin.chain = new_longest_chain
        bitcoin.pending_transactions = new_pending_transactions
        return jsonify({
            'note': 'This chain has been replaced.',
            'chain': bitcoin.chain
        })

@app.route('/block/<block_hash>')
def block(block_hash):
    block_data = bitcoin.get_block(block_hash)
    return jsonify({'block': block_data})

@app.route('/transaction/<transaction_id>')
def transaction(transaction_id):
    transaction_data = bitcoin.get_transaction(transaction_id)
    return jsonify({
        'transaction': transaction_data['transaction'],
        'block': transaction_data['block']
    })

@app.route('/address/<address>')
def address(address):
    address_data = bitcoin.get_address_data(address)
    return jsonify({'addressData': address_data})

@app.route('/block-explorer')
def block_explorer():
    return send_from_directory(app.static_folder, 'index.html')

#미결 트랜잭션들의 해시값들로 머클 트리를 만들고 머클 루트값을 반환하는 api
@app.route('/merkle-tree', methods=['POST'])
def generate_merkle_tree():
    transactions = bitcoin.pending_transactions

    if not transactions or not isinstance(transactions, list):
        return jsonify({'error': 'Invalid transactions'}), 400

    transaction_hashes = [bitcoin.hash_function(str(tx)) for tx in transactions]
    merkle_root = bitcoin.create_merkle_tree(transaction_hashes)

    return jsonify({'merkle_root': merkle_root}), 200


if __name__ == "__main__":
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    else:
        port = 5000  # 기본 포트 번호를 설정하십시오.
    
    #current_node_url = requests.get('http://ipv4.icanhazip.com').text.strip()
    #current_node_url = f"http://{current_node_url}:{port}"
    current_node_url = f"http://localhost:{port}"
    bitcoin = Blockchain(current_node_url)  # 현재 노드 URL 전달
    app.run(host="0.0.0.0", port=port)