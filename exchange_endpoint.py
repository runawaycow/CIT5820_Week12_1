from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import sys

from models import Base, Order, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


""" Suggested helper methods """

def check_sig(payload,sig):
    platform = payload['platform']
    if platform == 'Algorand':
        return verify_algo_signature(payload, sig, payload['sender_pk'])
    elif platform == 'Ethereum':
        return verify_eth_signature(payload, sig, payload['sender_pk'])
    else:
        return False

def fill_order(order,txes=[]):
    #Your code here
    #if all(key in order for key in ['sender_pk','buy_amount','sell_amount', 'receiver_pk', 'buy_currency', 'sell_currency']):
        order_obj = order
        
        for existing_order in session.query(Order).all():
            if order_obj.sell_amount * existing_order.sell_amount >= order_obj.buy_amount * existing_order.buy_amount and existing_order.buy_currency == order.sell_currency and existing_order.sell_currency == order.buy_currency and existing_order.filled == None:
                order_obj.filled = func.now()
                existing_order.filled = func.now()
                order_obj.counterparty_id = existing_order.id
                existing_order.counterparty_id = order_obj.id
                if order_obj['buy_amount']>existing_order['sell_amount']:
                    order_r = {}
                    order_r['filled'] = None
                    order_r['creator_id'] = order_obj['id']
                    order_r['sender_pk'] = order_obj['sender_pk']
                    order_r['receiver_pk'] = order_obj['receiver_pk']
                    order_r['buy_currency'] = order_obj['buy_currency']
                    order_r['sell_currency'] = order_obj['sell_currency']
                    order_r['buy_amount'] = order_obj['buy_amount']-existing_order['sell_amount']
                    order_r['sell_amount'] = order_obj['sell_amount']-existing_order['buy_amount']
                    session.add(order_r)
                    session.add(order_obj)
                elif existing_order['buy_amount']>order_obj['sell_amount']:
                    order_r = {}
                    order_r['filled'] = None
                    order_r['creator_id'] = existing_order['id']
                    order_r['sender_pk'] = existing_order['sender_pk']
                    order_r['receiver_pk'] = existing_order['receiver_pk']
                    order_r['buy_currency'] = existing_order['buy_currency']
                    order_r['sell_currency'] = existing_order['sell_currency']
                    order_r['buy_amount'] = existing_order['buy_amount']-order_obj['sell_amount']
                    order_r['sell_amount'] = existing_order['sell_amount']-order_obj['buy_amount']
                    session.add(order_r)
                    session.add(order_obj)                            
            g.session.commit()
            txes.append(order_obj)
            txes.append(existing_order)
            break
    return txes
  
def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    # Hint: use json.dumps or str() to get it in a nice string form
    log_entry = Log(message=json.dumps(d))
    g.session.add(log_entry)
    g.session.commit()

def verify_eth_signature(payload, signature, public_key):
    message = json.dumps(payload)
    message_hash = eth_account.messages.encode_defunct(text=message)
    try:
        recovered = eth_account.Account.recover_message(message_hash, signature=signature)
        return public_key.lower() == recovered.lower()
    except:
        return False

def verify_algo_signature(payload, signature, public_key):
    message = json.dumps(payload)
    try:
        recovered = algosdk.util.verify_bytes(message.encode('utf-8'), signature, public_key)
        return True
    except:
        return False
        # Verify the signature
        sig = content['sig']
        payload = content['payload']
        platform = payload['platform']
        if platform == 'Algorand':
            if not verify_algo_signature(payload, sig, payload['sender_pk']):
                log_message(content)
                return jsonify(False)
        elif platform == 'Ethereum':
            if not verify_eth_signature(payload, sig, payload['sender_pk']):
                log_message(content)
                return jsonify(False)
        else:
            log_message(content)
            return jsonify(False)

        # Insert the order into the database
        order = Order(sender_pk=payload['sender_pk'], receiver_pk=payload['receiver_pk'],
                      buy_currency=payload['buy_currency'], sell_currency=payload['sell_currency'],
                      buy_amount=payload['buy_amount'], sell_amount=payload['sell_amount'], signature=sig)
        g.session.add(order)
        g.session.commit()

        return jsonify(True)
""" End of helper methods """



@app.route('/trade', methods=['POST'])
def trade():
    print("In trade endpoint")
    if request.method == "POST":
        content = request.get_json(silent=True)
        print( f"content = {json.dumps(content)}" )
        columns = [ "sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform" ]
        fields = [ "sig", "payload" ]

        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
        
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
            
        #Your code here
        #Note that you can access the database session using g.session

        # TODO: Check the signature
        sig = content['sig']
        payload = content['payload']
        platform = payload['platform']
        if platform == 'Algorand':
            if not verify_algo_signature(payload, sig, payload['sender_pk']):
                log_message(content)
                return jsonify(False)
        elif platform == 'Ethereum':
            if not verify_eth_signature(payload, sig, payload['sender_pk']):
                log_message(content)
                return jsonify(False)
        else:
            log_message(content)
            return jsonify(False)

        # TODO: Add the order to the database
        order = Order(sender_pk=payload['sender_pk'], receiver_pk=payload['receiver_pk'],
                      buy_currency=payload['buy_currency'], sell_currency=payload['sell_currency'],
                      buy_amount=payload['buy_amount'], sell_amount=payload['sell_amount'], signature=sig)
        g.session.add(order)
        g.session.commit()

        # TODO: Fill the order
        fill_order(order)

        # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful
        return jsonify(True)

@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
    # Retrieve all orders from the database
    orders = g.session.query(Order).all()

    # Convert orders to a list of dictionaries
    result = []
    for order in orders:
        result.append({'sender_pk': order.sender_pk,
                       'receiver_pk': order.receiver_pk,
                       'buy_currency': order.buy_currency,
                       'sell_currency': order.sell_currency,
                       'buy_amount': order.buy_amount,
                       'sell_amount': order.sell_amount,
                       'signature': order.signature})

    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')