"""
运行 examples 下的例子代码
"""

import pathlib
from typing import List, Union

script_dir = pathlib.Path(__file__).parent.resolve()


def run_example_codes():
    print("----------------sm2_encrypt_and_decrypt----------------")
    import examples.sm2_encrypt_and_decrypt

    print("----------------sm2_sign_and_verify----------------")
    import examples.sm2_sign_and_verify

    print("----------------sm2_asn1_der----------------")
    import examples.sm2_asn1_der

    print("----------------sm2_key----------------")
    import examples.sm2_key

    print("----------------sm3_hash----------------")
    import examples.sm3_hash

    print("----------------sm3_hmac----------------")
    import examples.sm3_hmac

    print("----------------sm3_kdf----------------")
    import examples.sm3_kdf

    print("----------------sm4_cbc_encrypt_and_decrypt----------------")
    import examples.sm4_cbc_encrypt_and_decrypt

    print("----------------sm4_ctr_encrypt_and_decrypt----------------")
    import examples.sm4_ctr_encrypt_and_decrypt

    print("----------------sm4_gcm_encrypt_and_decrypt----------------")
    import examples.sm4_gcm_encrypt_and_decrypt

    print("----------------sm9_encrypt_and_decrypt----------------")
    import examples.sm9_encrypt_and_decrypt


def extract_code_from_md(md_path: Union[str, pathlib.Path]) -> List[str]:
    """
    从 markdown 文件中提取代码块
    """
    md_path = pathlib.Path(md_path)
    code_blocks = []
    in_code_block = False
    current_block = []

    with md_path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip().startswith("```"):
                if in_code_block:
                    # 结束代码块
                    code_blocks.append("".join(current_block))
                    current_block = []
                    in_code_block = False
                else:
                    # 开始代码块
                    in_code_block = True
            elif in_code_block:
                current_block.append(line)

    return code_blocks


def execute_code(code: str):
    """
    执行一段代码
    """
    # 判断代码块是否合法的 Python 代码
    try:
        code_type = compile(code, "<string>", "exec")
    except Exception:
        return

    try:
        exec(code_type)
    except Exception as e:
        print(f"代码块内容:\n{code}")
        raise


def run_code_from_md(md_path: Union[str, pathlib.Path]):
    """
    从 markdown 文件中提取代码块并运行
    """
    code_blocks = extract_code_from_md(md_path)
    for code in code_blocks:
        execute_code(code)


def main():
    run_example_codes()

    print("---------------- README.md ----------------")
    md_file = script_dir / "README.md"
    run_code_from_md(md_file)

    print("---------------- docs/sm9.md ----------------")
    md_file = script_dir / "docs" / "sm9.md"
    run_code_from_md(md_file)


if __name__ == "__main__":
    main()
