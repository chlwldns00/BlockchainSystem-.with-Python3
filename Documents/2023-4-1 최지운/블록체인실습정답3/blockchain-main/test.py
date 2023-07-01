# main.py
from app.blockchain import Blockchain

def main():
    # Blockchain 생성자를 이용해 인스턴스를 생성하고, 필요한 인자를 전달합니다.
    bitcoin = Blockchain()

    # previous_block_hash = '519619156945694516'
    # current_block_data = [
    #     {
    #         'amount' : 10,
    #         'sender' : 'BAD48461AB6',
    #         'recipient' : 'ag4a6e4g9a4w5eg',
    #     },
    #     {
    #         'amount' : 30,
    #         "sender" : '15DSGA86G4AD46GAE',
    #         'recipient' : 'aega6we16ga1we65g1',
    #     },
    #     {
    #         'amount' : 100,
    #         "sender" : 'GAWEKGAWE66GA16W1E1661',
    #         'recipient' : 'a6w191a9be156b1a',
    #     },
    # ]
    # nonce = 100


    bc1 = {
    "chain": [
    {
      "hash": "0000b6ffb1077e7c228776a2df9df7c6c5cb2021168b4e908e3f3eee9952f298",
      "index": 1,
      "merkel_tree_process": [
        "2aac6b6b862969233e911edcc19b52e3608f2608ce29e7cfcefa9589f0950429",
        "2aac6b6b862969233e911edcc19b52e3608f2608ce29e7cfcefa9589f0950429",
        "b2c413217b0088e45fbabba8ef50ca8509ffbabc74e0e439bc42dd23dba92eff"
      ],
      "merkle_root": "b2c413217b0088e45fbabba8ef50ca8509ffbabc74e0e439bc42dd23dba92eff",
      "nonce": 75936,
      "previous_block_hash": "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",
      "timestamp": 1684908914667,
      "transactions": [
        {
          "amount": 50,
          "recipient": "494f87366956418587e9df3d2e5401db",
          "sender": "0",
          "transaction_id": "9dcc37ba0d344c2c9aabaddb83c8bee9"
        }
      ]
    }
  ],
  "current_node_url": "http://220.67.133.67:5000",
  "network_nodes": [ ],
  "pending_transactions": {
    "amount": 6.25,
    "recipient": "f858681aff0e4b10b3b542e3bf4af444",
    "sender": "00",
    "transaction_id": "8717d8c0bf6f49838c2db7fc9e53bab6"
  }
}
    

    print('VALID:', bitcoin.chain_is_valid(bc1['chain']))
    #print(bitcoin.hash_block(previous_block_hash,current_block_data,900))

if __name__ == "__main__":
    main()
