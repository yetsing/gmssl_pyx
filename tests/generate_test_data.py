import json
import sys
from pathlib import Path

script_dir = Path(__file__).parent.resolve()
data_dir = script_dir / "data"
data_dir.mkdir(exist_ok=True)

sys.path.insert(0, str(script_dir.parent))
from gmssl_pyx import SM9MasterKey, SM9MasterPublicKey, SM9PrivateKey, sm2_key_generate

def generate_sm2():
    d = []
    for _ in range(16):
        public_key, private_key = sm2_key_generate()
        d.append({
            "public_key": public_key.hex(),
            "private_key": private_key.hex(),
        })
    with open(data_dir / "sm2_generated_key.json", "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=4)


def generate_sm9():
    # 生成主密钥
    master = SM9MasterKey.generate()
    # 根据主密钥生成公钥和私钥
    identity = "张三".encode()
    public_key = master.public_key()
    private_key = master.extract_key(identity)
    # 公私钥导出 pem
    public_pem_filename = data_dir / "sm9_public.pem"
    public_key.to_pem(str(public_pem_filename))
    password = "your password"
    private_pem_filename = data_dir / "sm9_private.pem"
    private_key.encrypt_to_pem(password, str(private_pem_filename))

    master.encrypt_to_pem(password, str(data_dir / "sm9_master.pem"))

    pub = public_key.to_der()
    priv = private_key.to_der()
    priv_encrypted = private_key.encrypt_to_der(password)
    d = {
        "identity": identity.hex(),
        "password": password,
        "public_key": pub.hex(),
        "private_key": priv.hex(),
        "private_key_encrypted": priv_encrypted.hex(),
    }
    with open(data_dir / "sm9_generated_key.json", "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=4)



def main():
    generate_sm2()
    generate_sm9()


if __name__ == "__main__":
    main()
