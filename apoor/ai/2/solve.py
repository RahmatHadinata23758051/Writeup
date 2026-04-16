import torch
import matplotlib.pyplot as plt

# Load tensors
base = torch.load('base_model.pt')
lora = torch.load('lora_adapter.pt')

# Target spesifik ke layer 2
W = base['layer2.weight']
A = lora['layer2.lora_A']
B = lora['layer2.lora_B']

print(f"Shape W (Base) : {W.shape}")
print(f"Shape A (LoRA) : {A.shape}")
print(f"Shape B (LoRA) : {B.shape}")

# Cari urutan perkalian yang dimensinya pas dengan W
if (A @ B).shape == W.shape:
    delta_W = A @ B
elif (B @ A).shape == W.shape:
    delta_W = B @ A
else:
    print("Wah, dimensinya masih nggak ada yang pas nih.")
    exit()

# "Together... well, that's for you to figure out."
W_new = W + delta_W

# Tampilkan visualisasi W_new
plt.imshow(W_new.detach().cpu().numpy(), cmap='gray')
plt.title("The Real Flag")
plt.axis('off') # Biar sumbu X dan Y gak ganggu gambar
plt.show()
