from tkinter import *
from tkinter import ttk, filedialog, messagebox
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import qrcode
from PIL import Image, ImageTk
import piexif

def generate_random_key():
    key_str = get_random_bytes(16).hex()
    key.set(key_str)
    generate_qr_code(key_str)

def generate_qr_code(key_str):
    if len(key_str) not in [16, 24, 32]:
        print("Invalid key length for QR code generation", flush=True)
        return

    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(key_str)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img = img.resize((200, 200), Image.LANCZOS)
        img_tk = ImageTk.PhotoImage(img)
        qr_label.config(image=img_tk, width=200, height=200)
        qr_label.image = img_tk
    except Exception as e:
        print(f"Error in generate_qr_code: {e}", flush=True)

def encrypt_message(save_to_file=True):
    key_str = key.get()
    if len(key_str) not in [16, 24, 32]:
        messagebox.showerror("Error", "Key must be 16, 24, or 32 characters long")
        return None
    key_bytes = key_str.encode()
    cipher_config = AES.new(key_bytes, AES.MODE_EAX)
    cipher_text, tag = cipher_config.encrypt_and_digest(msg.get("1.0", END).encode())
    if save_to_file:
        file_out = filedialog.asksaveasfile(mode='wb', filetypes=[("text files", "*.txt")])
        [file_out.write(x) for x in (cipher_config.nonce, tag, cipher_text)]
        file_out.close()
    return cipher_config.nonce + tag + cipher_text

def embed_in_image(data):
    image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    image = Image.open(image_path)

    exif_dict = piexif.load(image.info['exif']) if 'exif' in image.info else None

    binary_data = bin(len(data))[2:].zfill(32) + ''.join(bin(i)[2:].zfill(8) for i in data)

    if len(binary_data) > len(image.getdata()) * 3:
        raise ValueError("Data is too large to embed in this image.")

    pixels = list(image.getdata())
    for i in range(len(binary_data)):
        pixel = list(pixels[i])
        pixel[i % 3] = int(bin(pixel[i % 3])[:-1] + binary_data[i], 2)
        pixels[i] = tuple(pixel)

    new_image = Image.new(image.mode, image.size)
    new_image.putdata(pixels)

    base_name, ext = os.path.splitext(image_path)
    new_image_path = f"{base_name}_embedded{ext}"
    counter = 1

    while os.path.exists(new_image_path):
        new_image_path = f"{base_name}_embedded_{counter}{ext}"
        counter += 1

    if exif_dict:
        exif_bytes = piexif.dump(exif_dict)
        new_image.save(new_image_path, exif=exif_bytes)
    else:
        new_image.save(new_image_path)

    print(f"Image saved as {new_image_path}")

def decrypt_message():
    file_in = filedialog.askopenfile(mode='rb', filetypes=[("text files", "*.txt")])
    nonce, tag, cipher_text = [file_in.read(x) for x in (16, 16, -1)]
    file_in.close()

    key_str = key.get()
    if len(key_str) not in [16, 24, 32]:
        messagebox.showerror("Error", "Key must be 16, 24, or 32 characters long")
        return

    key_bytes = key_str.encode()
    cipher_config = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce)
    plain_text = cipher_config.decrypt_and_verify(cipher_text, tag)

    decrypted_msg.config(state="normal")
    decrypted_msg.delete("1.0", END)
    decrypted_msg.insert(END, plain_text.decode())
    decrypted_msg.config(state="disabled")

def extract_from_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    img = Image.open(file_path)
    pixels = list(img.getdata())
    binary_data = ''.join(bin(pixel[i % 3])[-1] for i, pixel in enumerate(pixels))

    data_length = int(binary_data[:32], 2)
    binary_data = binary_data[32:32 + data_length * 8]

    data = bytearray(int(binary_data[i: i + 8], 2) for i in range(0, len(binary_data), 8))

    nonce, tag, cipher_text = data[:16], data[16:32], data[32:]

    key_str = key.get()
    if len(key_str) not in [16, 24, 32]:
        messagebox.showerror("Error", "Key must be 16, 24, or 32 characters long")
        return

    key_bytes = key_str.encode()
    cipher_config = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce)
    plain_text = cipher_config.decrypt_and_verify(cipher_text, tag)

    decrypted_msg.config(state="normal")
    decrypted_msg.delete("1.0", END)
    decrypted_msg.insert(END, plain_text.decode())
    decrypted_msg.config(state="disabled")

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(decrypted_msg.get("1.0", END))
    messagebox.showinfo("Success", "Message copied to clipboard")

def on_key_release(event):
    root.after(500, update_qr_code)

def update_qr_code():
    key_str = key.get()
    generate_qr_code(key_str)

root = Tk()
root.title("StealthCrypt")
style = ttk.Style()


key_frame = ttk.LabelFrame(root, text="Key")
key_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

key = StringVar()
Label(key_frame, text="Enter your key:").grid(row=0, column=0, padx=5, pady=5)
key_entry = Entry(key_frame, textvariable=key, width=50)
key_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
key_entry.bind("<KeyRelease>", on_key_release)
Button(key_frame, text="Generate random key", command=generate_random_key).grid(row=0, column=2, padx=5, pady=5)
key_frame.grid_columnconfigure(1, weight=1)

msg_frame = ttk.LabelFrame(root, text="Message")
msg_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)

Label(msg_frame, text="Enter your message:")
msg = Text(msg_frame, height=5)
msg.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
scrollbar = ttk.Scrollbar(msg_frame, orient=VERTICAL, command=msg.yview)
scrollbar.grid(row=1, column=1, sticky="ns")
msg['yscrollcommand'] = scrollbar.set
msg_frame.grid_columnconfigure(0, weight=1)
msg_frame.grid_rowconfigure(1, weight=1)

decrypted_frame = ttk.LabelFrame(root, text="Decrypted Message")
decrypted_frame.grid(row=5, column=0, sticky="nsew", padx=5, pady=5)

decrypted_msg = Text(decrypted_frame, state="disabled", height=5)
decrypted_msg.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
decrypted_scrollbar = ttk.Scrollbar(decrypted_frame, orient=VERTICAL, command=decrypted_msg.yview)
decrypted_scrollbar.grid(row=0, column=1, sticky="ns")
decrypted_msg['yscrollcommand'] = decrypted_scrollbar.set
decrypted_frame.grid_columnconfigure(0, weight=1)
decrypted_frame.grid_rowconfigure(0, weight=1)

Button(decrypted_frame, text="Copy to clipboard", command=copy_to_clipboard).grid(row=1, column=0, padx=5, pady=5, sticky="ew")

right_column_frame = Frame(root, width=250)
right_column_frame.grid(row=0, column=1, rowspan=6, sticky="ns", padx=5, pady=5)
right_column_frame.grid_propagate(False)

qr_frame = ttk.LabelFrame(right_column_frame, text="QR Code", width=250, height=250, padding=(25, 12))
qr_frame.grid(row=0, column=0)
qr_frame.grid_propagate(False)
qr_label = Label(qr_frame)
qr_label.grid(sticky="nsew")

enc_dec_frame = ttk.LabelFrame(right_column_frame, text="Encryption/Decryption", width=250)
enc_dec_frame.grid(row=1, column=0, sticky="ns", padx=5, pady=5)

Button(enc_dec_frame, text="Encrypt", command=encrypt_message).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
Button(enc_dec_frame, text="Decrypt", command=decrypt_message).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
Button(enc_dec_frame, text="Embed in image", command=lambda: embed_in_image(encrypt_message(save_to_file=False))).grid(row=1, column=0, padx=5, pady=5, sticky="ew")
Button(enc_dec_frame, text="Extract from image", command=extract_from_image).grid(row=1, column=1, padx=5, pady=5, sticky="ew")
enc_dec_frame.grid_columnconfigure(0, weight=1)
enc_dec_frame.grid_columnconfigure(1, weight=1)

root.grid_rowconfigure(2, weight=1)
root.grid_rowconfigure(5, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, minsize=250)

root.mainloop()
