from flask import Flask, request, render_template,session
import requests
import flask_profiler
from pymongo import MongoClient
import bcrypt
import json
import time
from hashlib import sha256
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
import base64

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    def compute_hash(self):
      
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()

    def print_contents(self):
        print("timestamp:", self.timestamp)
        print("transactions:", self.transactions)
        print("current hash:", self.hash)
        print("previous hash:", self.previous_hash) 
        
class Blockchain:
    # difficulty of our PoW algorithm
    difficulty = 2

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []

    def create_genesis_block(self):

        genesis_block = Block(0, [], 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not Blockchain.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)
        
        return True
        
    def print_blocks(self):
        for i in range(len(self.chain)):
            current_block = self.chain[i]
            print("Block {} {}".format(i, current_block))
            current_block.print_contents()

    def proof_of_work(block):
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)
        self.mine()
        self.print_blocks()

    def is_valid_proof(cls, block, block_hash):

        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"

        for block in chain:
            block_hash = block.hash
            delattr(block, "hash")

            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.previous_hash:
                result = False
                break

            block.hash, previous_hash = block_hash, block_hash

        return result

    def mine(self):

        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []
        

        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
 
            announce_new_block(blockchain.last_block)
        return "Block #{} is mined.".format(blockchain.last_block.index)

app = Flask(__name__, template_folder='templates')

app.secret_key = 'PATREC Authentication'
client = MongoClient('localhost', 27017)

db = client.Ehealth
records = db.users


blockchain = Blockchain()
blockchain.create_genesis_block()
peers = set()
@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/DoctorLogin')
def doc_login():
    return render_template('DoctorLogin.html')
    
@app.route('/patientlogin')
def patient_login():
    return render_template('patientlogin.html') 
    
@app.route('/SignUp')
def signup():
    return render_template('doctor_signup.html') 
@app.route('/pat_SignUp')
def pat_signup():
    return render_template('patient_signup.html') 

@app.route('/dashboard')
def dashboard():
    return render_template('Doctor_Dash.html') 


@app.route('/Createrecord')
def createrecord():
    return render_template('medrecord.html') 

@app.route("/handle_Login", methods=["POST", "GET"])
def handle_login():
    print("Inside handle")
    if request.method == "POST":
        user = request.form.get("username")
        password = request.form.get("password")
        user_found = records.find_one({"name": user})
        if user_found:
            user_val = user_found['name']
            passwordcheck = user_found['password']
            print(user_val, passwordcheck)
            print(user, password)
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session['user'] = user_val
                print("session", session['user'])
                return render_template('Doctor_Dash.html', message= user_val)
            else:
               
                message = 'Wrong Password'
                return render_template('DoctorLogin.html', message=message)
        else:
            message = 'User not found'
            return render_template('DoctorLogin.html', message=message)
            
@app.route("/handle_patientlogin", methods=["POST", "GET"])
def handle_patientlogin():
    print("Inside handle")
    if request.method == "POST":
        user = request.form.get("username")
        password = request.form.get("password")
        user_found = records.find_one({"name": user})
        if user_found:
            user_val = user_found['name']
            passwordcheck = user_found['password']
            print(user_val, passwordcheck)
            print(user, password)
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session['user'] = user_val
                print("session", session['user'])
                return render_template('Patient_Dash.html', message= user_val)
            else:
               
                message = 'Wrong Password'
                return render_template('patientlogin.html', message=message)
        else:
            message = 'User not found'
            return render_template('patientlogin.html', message=message)             
    
@app.route('/handle_data', methods=['POST'])
def handle_data():
 if request.method == "POST":
        user = request.form.get("username")
        email = request.form.get("emailaddress")
        
        password1 = request.form.get("password")
        password2 = request.form.get("password2")
        
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'UserName Already Exists'
            return render_template('patient_signup.html', message=message)
        if email_found:
            message = 'Email Already Exists'
            return render_template('patient_signup.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('patient_signup.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            records.insert_one(user_input)
            
            user_data = records.find_one({"email": email})
            new_email = user_data['email']
   
        return render_template('DoctorLogin.html', message="Please Login Now !!")
        
@app.route('/handle_patientdata', methods=['POST'])
def handle_patientdata():
 if request.method == "POST":
        user = request.form.get("username")
        email = request.form.get("emailaddress")
        
        password1 = request.form.get("password")
        password2 = request.form.get("password2")
        
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'UserName Already Exists'
            return render_template('patient_signup.html', message=message)
        if email_found:
            message = 'Email Already Exists'
            return render_template('patient_signup.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('patient_signup.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            records.insert_one(user_input)
            
            user_data = records.find_one({"email": email})
            new_email = user_data['email']
   
        return render_template('patientlogin.html', message="Please Login Now !!")

@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    #required contents of the block
    patient_id = request.form.get("pid")
    doctor_id = request.form.get("docid")
    first_name = request.form.get("first")
    last_name = request.form.get("last")
    gender = request.form.get("gen")
    age = request.form.get("age")
    weight = request.form.get("wt")
    height = request.form.get("ht")
    disease = request.form.get("disease")
    
    
    print("called")
    
    if not (patient_id and doctor_id):
        return render_template('Doctor_Dash.html', message = "Please check the Information") 
    
    blockchain.add_new_transaction({"patient_id":patient_id, "doctor_id":doctor_id , "first_name": first_name, "last_name":                     last_name,"age":age,"weight":weight, "gender": gender, "height":height, "disease":disease})
    
    return render_template('Doctor_Dash.html',) 
        

@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,"peers": list(peers)})


# Endpoint to add new peers to the network
@app.route('/register_node', methods=['POST'])
def register_new_peers():
    print("Inside Register new peers")
    # The host address to the peer node 
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    # Add the node to the peer list
    peers.add(node_address)
    print("inside register new : " ,peers)
    
    return get_chain()

@app.route('/register_with', methods=['POST'])
def register_with():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}
    url = node_address + "/register_node"   
    response = requests.post(url, data=json.dumps(data), headers=headers)
    if response.status_code ==200:
        global blockchain
        global peers
        chain_dump = response.json()['chain']
        print("CHAIN_DUMP", chain_dump)
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
        return "Registration successful", 200
    else:
        return response.content, response.status_code
        
    
@app.route('/append_explicitly', methods=["POST"])
def append_explicitly():
    res = request.get_json()["newP"]
    print(res)
    peers.append(res)
    print(peers)
    return "Done", 200
    
def create_chain_from_dump(chain_dump):
    generated_blockchain = Blockchain()
    generated_blockchain.create_genesis_block()
    for idx, block_data in enumerate(chain_dump):
        if idx == 0:
            continue  
        block = Block(block_data["index"],
                      block_data["transactions"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']
        added = generated_blockchain.add_block(block, proof)
        if not added:
            raise Exception("The chain dump is tampered!!")
    generated_blockchain.print_blocks()
    return generated_blockchain
    
@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data['hash']
    added = blockchain.add_block(block, proof)

    if not added:
        return "The block was discarded by the node", 400

    return "Block added to the chain", 201


def announce_new_block(block):
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(block.__dict__, sort_keys=True),
                      headers=headers)
                      
def consensus():

    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        response = requests.get('{}chain'.format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        blockchain = longest_chain
        return True

    return False            
        
        
@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)

@app.route('/display',methods=['post'])
def display():
    
    
    patient_id = request.form['_id']
    doctor_id = request.form['doc_id']
    first_name = request.form['fname']
    last_name = request.form['lname']    
    age = request.form['age']  
    weight = request.form['weight'] 
    gender = request.form['gender']          
    height = request.form['height']  
    disease = request.form['disease']  
    myview = {'patient_id': patient_id, 'doctor_id':doctor_id, 'first_name':first_name, 'last_name':last_name, 'age':age ,'weight':weight,'gender':gender,'height':height, 'disease': disease}
    return render_template('individualrec.html',post=myview)
    
    

@app.route('/get_data', methods=['GET'])
def retrieve():
    print(session['user'])
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)

    transactions =[]            
    for i in range(0, len(chain_data)):
        if(len(chain_data[i]['transactions']) !=0 and chain_data[i]['transactions'][0]['doctor_id'] == session['user']):
            transactions.append(chain_data[i]['transactions'][0])
    print(transactions)
                        
    return render_template("records.html", available_records = transactions)
    
@app.route('/get_patdata', methods=['GET'])
def retrieve_pat():
    print(session['user'])
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    transactions =[]            
    for i in range(0, len(chain_data)):
        if(len(chain_data[i]['transactions']) !=0 and chain_data[i]['transactions'][0]['patient_id'] == session['user']):
            transactions.append(chain_data[i]['transactions'][0])
                        
    return render_template("records.html", available_records = transactions)
    
@app.route('/logout')
def logout():
    if 'user' in session:
        session.pop('user',None)
    return render_template('DoctorLogin.html')
@app.route('/logout_pat')  
def logout_pat():
    if 'user' in session:
        session.pop('user',None)
    return render_template('patientlogin.html')
       

if __name__ == "__main__":
    app.run(debug=True)