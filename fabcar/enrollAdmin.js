'use strict';
/*
* Copyright IBM Corp All Rights Reserved
*
* SPDX-License-Identifier: Apache-2.0
*/
/*
 * Enroll the admin user
 */

var Fabric_Client = require('fabric-client');
var Fabric_CA_Client = require('fabric-ca-client');

var path = require('path');
var util = require('util');
var os = require('os');

//
var fabric_client = new Fabric_Client();
var fabric_ca_client = null;
var admin_user = null;
var member_user = null;
var store_path = path.join(__dirname, 'hfc-key-store');
console.log(' Store path:'+store_path);


/*
관리자를 통해 사용자를 만드는 단계

1. 로컬 저장소에서 관리 사용자 자격 증명 불러오기
2. 해당 자격 증명이 존재하지 않으면 관리자를 Fabric-CA 서버에 등록하고 자격 증명(개인 키 및 등록 인증서)를 가져온다.
3. 관리자가 주어진 ID, 역할, 소속에 대한 사용자를 Fabric CA 서버로 등록
4. 등록시 반환되는 비밀번호를 사용하여 해당 사용자의 자격 증명을 얻는다
5. 로컬 저장소에 자격 증명을 저장

*/

// key-value store를 생성해서  fabric-client/config/default.json 'key-value-store'에 저장.
 //state_store : user's certificate 저장소
Fabric_Client.newDefaultKeyValueStore({ path: store_path
}).then((state_store) => {
   
    fabric_client.setStateStore(state_store); //fabric client에도 state_store 할당
    var crypto_suite = Fabric_Client.newCryptoSuite(); // CryptoSuite : 디지털 서명, 암호화/암호 해독 및 보안 해싱을 수행하기 위해 SDK에서 사용하는 암호화 알고리즘 추상 클래스
    
    //crypto store : user's key 저장소  -> state_store와 같은 위치에 저장

    // use the same location for the state store (where the users' certificate are kept)
    // and the crypto store (where the users' keys are kept)
    var crypto_store = Fabric_Client.newCryptoKeyStore({path: store_path}); 
    crypto_suite.setCryptoKeyStore(crypto_store);
    fabric_client.setCryptoSuite(crypto_suite);
    var	tlsOptions = { //TLS : 인터넷 상에서 통신할 때 주고받는 데이터를 보호하기 위한 표준화된 암호화 프로토콜 -> 인증, 암호화, 무결성 지원
    	trustedRoots: [],
    	verify: false
    };
    // be sure to change the http to https when the CA is running TLS enabled
    fabric_ca_client = new Fabric_CA_Client('http://localhost:7054', tlsOptions , 'ca.example.com', crypto_suite);

    // admin이 등록이 되어있는지 확인한다
    return fabric_client.getUserContext('admin', true);
}).then((user_from_store) => {
    if (user_from_store && user_from_store.isEnrolled()) {
        console.log('Successfully loaded admin from persistence');
        admin_user = user_from_store;
        return null;
    } else {
        // need to enroll it with CA server
        return fabric_ca_client.enroll({
          enrollmentID: 'admin',
          enrollmentSecret: 'adminpw'
        }).then((enrollment) => {
          console.log('Successfully enrolled admin user "admin"');
          return fabric_client.createUser(
              {username: 'admin',
                  mspid: 'Org1MSP',
                  cryptoContent: { privateKeyPEM: enrollment.key.toBytes(), signedCertPEM: enrollment.certificate }
              });
        }).then((user) => {
          admin_usedmin_user = user;
          return fabric_client.setUserContext(admin_user);
        }).catch((err) => {
          console.error('Failed to enroll and persist admin. Error: ' + err.stack ? err.stack : err);
          throw new Error('Failed to enroll admin');
        });
    }
}).then(() => {
    console.log('Assigned the admin user to the fabric client ::' + admin_user.toString());
}).catch((err) => {
    console.error('Failed to enroll admin: ' + err);
});
