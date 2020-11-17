ECDSA 기반 key pair (private, public key) 생성 비트코인의 주소 체계와 같은 주소 생성 임의의 데이터(문자열)을 private key로 signature 생성, Public key를 이용하여 검증

디지털 키
비트코인 주소
디지털 서명 비트코인의 소유권이 성립된다.



실행 java -jar AddrDigSig.jar

공개키: 3056301006072a8648ce3d020106052b8104000a0342000430a69bafe6b0b4d1a7a46d181db1b63bcac87b0092454cc902eb0fc022274394546e5901c4e2c1c14d0c02393cf46e76ed7e5a46dfb3be00e21a3b213978e0bc 


개인키: 303e020100301006072a8648ce3d020106052b8104000a042730250201010420b3e0673eedc2582d36741cd7502470b3176b517559ad673009b3df8c8bc86900 Bitcoin Address: 1GVsscSys19nXbNEJi5g1Z1y8UawVFkeDn 

서명내용을 입력하세요  <-- input

안녕하세요 사인입니다 <-- 사용자 입력


json data: {"signature":"MEUCIHE40LaUlmPePWErAnRBECyTBkQndop4UTH86H3znaJrAiEAomfHVpO85jGXkBF6zrG6X6F72IBvudhbQVD37lH4yyQ=","publicKey":"MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEMKabr+awtNGnpG0YHbG2O8rIewCSRUzJAusPwCInQ5RUblkBxOLBwU0MAjk89G527X5aRt+zvgDiGjshOXjgvA==","message":"안녕하세요","algorithm":"SHA256withECDSA"}

디지털사인 데이터:{"signature":"MEUCIHE40LaUlmPePWErAnRBECyTBkQndop4UTH86H3znaJrAiEAomfHVpO85jGXkBF6zrG6X6F72IBvudhbQVD37lH4yyQ=","publicKey":"MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEMKabr+awtNGnpG0YHbG2O8rIewCSRUzJAusPwCInQ5RUblkBxOLBwU0MAjk89G527X5aRt+zvgDiGjshOXjgvA==","message":"안녕하세요","algorithm":"SHA256withECDSA"}

서명 데이터 확인 :true
