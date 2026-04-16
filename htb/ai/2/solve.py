import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

print("[*] Memuat data dari token_embeddings.npz...")
data = np.load('token_embeddings.npz')
tokens = data['tokens']
embeddings = data['embeddings']

print(f"[+] Ditemukan {len(tokens)} token.")

# KUNCI JAWABAN: Proyeksikan ke 3 Dimensi sesuai hint!
print("[*] Menjalankan PCA ke 3D...")
pca = PCA(n_components=3)
embeddings_3d = pca.fit_transform(embeddings)

print("[*] Membuka grafik 3D interaktif...")
fig = plt.figure(figsize=(10, 8))
# Membuat canvas 3D
ax = fig.add_subplot(111, projection='3d')

# Meletakkan teks di koordinat 3D
for i, token in enumerate(tokens):
    ax.text(embeddings_3d[i, 0], embeddings_3d[i, 1], embeddings_3d[i, 2], 
            token, fontsize=12, fontweight='bold')

# Menyesuaikan batas sumbu agar tidak ada yang terpotong
ax.set_xlim(embeddings_3d[:,0].min(), embeddings_3d[:,0].max())
ax.set_ylim(embeddings_3d[:,1].min(), embeddings_3d[:,1].max())
ax.set_zlim(embeddings_3d[:,2].min(), embeddings_3d[:,2].max())

plt.title("Putar grafik ini dengan Mouse untuk menemukan angle yang pas!")
plt.axis('off') # Matikan garis sumbu biar bersih
plt.show()
