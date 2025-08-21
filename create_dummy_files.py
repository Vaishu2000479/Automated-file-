import os
import random
import string

root = "dummy_test_files"
os.makedirs(root, exist_ok=True)

folders = [
    "images", "documents", "executables", "archives", "scripts", "audio", "video", "random", "mixed"
]
for folder in folders:
    os.makedirs(os.path.join(root, folder), exist_ok=True)

# Create a separate folder for infected files
infected_folder = os.path.join(root, "infected")
os.makedirs(infected_folder, exist_ok=True)

def random_bytes(size):
    return bytes(random.getrandbits(8) for _ in range(size))

def random_name(ext):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8)) + ext

# 1. Images (JPEG, PNG, GIF)
for _ in range(15):
    with open(os.path.join(root, "images", random_name(".jpg")), "wb") as f:
        f.write(b"\xFF\xD8\xFF" + random_bytes(1000))
    with open(os.path.join(root, "images", random_name(".png")), "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + random_bytes(1000))
    with open(os.path.join(root, "images", random_name(".gif")), "wb") as f:
        f.write(b"GIF89a" + random_bytes(1000))

# 2. Documents (PDF, DOCX, TXT, CSV)
for _ in range(15):
    with open(os.path.join(root, "documents", random_name(".pdf")), "wb") as f:
        f.write(b"%PDF-1.4\n" + random_bytes(1000))
    with open(os.path.join(root, "documents", random_name(".docx")), "wb") as f:
        f.write(b"PK\x03\x04" + random_bytes(1000))  # DOCX is a zip
    with open(os.path.join(root, "documents", random_name(".txt")), "w") as f:
        f.write("Dummy text file\n" + ''.join(random.choices(string.printable, k=100)))
    with open(os.path.join(root, "documents", random_name(".csv")), "w") as f:
        f.write("col1,col2,col3\n" + ','.join(str(random.randint(0, 100)) for _ in range(30)))

# 3. Executables (EXE, DLL, ELF, SO)
for _ in range(10):
    with open(os.path.join(root, "executables", random_name(".exe")), "wb") as f:
        f.write(b"MZ" + random_bytes(1000))
    with open(os.path.join(root, "executables", random_name(".dll")), "wb") as f:
        f.write(b"MZ" + random_bytes(1000))
    with open(os.path.join(root, "executables", random_name(".elf")), "wb") as f:
        f.write(b"\x7fELF" + random_bytes(1000))
    with open(os.path.join(root, "executables", random_name(".so")), "wb") as f:
        f.write(b"\x7fELF" + random_bytes(1000))

# 4. Archives (ZIP, RAR, 7z)
for _ in range(10):
    with open(os.path.join(root, "archives", random_name(".zip")), "wb") as f:
        f.write(b"PK\x03\x04" + random_bytes(1000))
    with open(os.path.join(root, "archives", random_name(".rar")), "wb") as f:
        f.write(b"Rar!\x1A\x07\x00" + random_bytes(1000))
    with open(os.path.join(root, "archives", random_name(".7z")), "wb") as f:
        f.write(b"7z\xBC\xAF\x27\x1C" + random_bytes(1000))

# 5. Scripts (PY, BAT, SH)
for _ in range(10):
    with open(os.path.join(root, "scripts", random_name(".py")), "w") as f:
        f.write("#!/usr/bin/env python3\nprint('Hello World')\n")
    with open(os.path.join(root, "scripts", random_name(".bat")), "w") as f:
        f.write("@echo off\necho Hello World\n")
    with open(os.path.join(root, "scripts", random_name(".sh")), "w") as f:
        f.write("#!/bin/bash\necho Hello World\n")

# 6. Audio/Video (MP3, MP4)
for _ in range(5):
    with open(os.path.join(root, "audio", random_name(".mp3")), "wb") as f:
        f.write(b"ID3" + random_bytes(1000))
    with open(os.path.join(root, "video", random_name(".mp4")), "wb") as f:
        f.write(b"\x00\x00\x00\x18ftypmp42" + random_bytes(1000))

# 7. Random binaries, high entropy, no extension
for _ in range(10):
    with open(os.path.join(root, "random", random_name("")), "wb") as f:
        f.write(random_bytes(2048))

# 8. Mixed/edge cases: mismatched extensions, EICAR, empty, large file, non-ASCII names
with open(os.path.join(root, "mixed", "eicar.txt"), "w") as f:
    f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
with open(os.path.join(root, "mixed", "image_as_pdf.pdf"), "wb") as f:
    f.write(b"\xFF\xD8\xFF" + random_bytes(1000))  # JPEG bytes, .pdf extension
with open(os.path.join(root, "mixed", "emptyfile.bin"), "wb") as f:
    pass
with open(os.path.join(root, "mixed", "largefile.bin"), "wb") as f:
    f.write(random_bytes(1024 * 1024))  # 1MB
with open(os.path.join(root, "mixed", "文件.txt"), "w", encoding="utf-8") as f:
    f.write("Non-ASCII filename\n")

# Infected files (EICAR and variants)
with open(os.path.join(infected_folder, "eicar.txt"), "w") as f:
    f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
with open(os.path.join(infected_folder, "eicar_com.com"), "w") as f:
    f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
with open(os.path.join(infected_folder, "eicar.pdf"), "wb") as f:
    f.write(b"%PDF-1.4\n" + b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" + random_bytes(1000))
with open(os.path.join(infected_folder, "eicar.exe"), "wb") as f:
    f.write(b"MZ" + b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" + random_bytes(1000))

# 9. More random files to reach 100-150 total
for _ in range(30):
    folder = random.choice(folders)
    ext = random.choice([".txt", ".jpg", ".exe", ".pdf", ".zip", ".py", ".bin", ".csv", ".mp3", ".mp4", ""])
    mode = "wb" if ext in [".jpg", ".exe", ".pdf", ".zip", ".mp3", ".mp4", ".bin", ""] else "w"
    path = os.path.join(root, folder, random_name(ext))
    with open(path, mode) as f:
        if mode == "wb":
            f.write(random_bytes(random.randint(500, 3000)))
        else:
            f.write("Dummy file\n" + ''.join(random.choices(string.printable, k=100)))

print("Dummy files created in:", root)