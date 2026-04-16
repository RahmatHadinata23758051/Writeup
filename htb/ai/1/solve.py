import numpy as np
import matplotlib.pyplot as plt
from sklearn.manifold import MDS
from sklearn.decomposition import PCA

def solve():
    print("[*] Loading and cleaning data...")
    matrix = np.load('distance_matrix.npy')
    
    # Gunakan n_init tinggi biar posisinya nggak lari-lari
    mds = MDS(n_components=2, dissimilarity='precomputed', random_state=42, n_init=10)
    coords = mds.fit_transform(matrix)
    
    # Luruskan pakai PCA
    pca = PCA(n_components=2)
    coords = pca.fit_transform(coords)
    
    x, y = coords[:, 0], coords[:, 1]

    # Visualisasi fokus teks
    plt.figure(figsize=(20, 5))
    
    # Kita hanya ambil bagian tengah (menghilangkan noise jauh)
    # s=0.5 biar bener-bener kayak font cetak
    plt.scatter(x, y, s=0.5, c='black', alpha=0.8)
    
    # Atur batas X agar tidak keganggu bayangan/mirroring di ujung
    # Berdasarkan plot kamu, area flag ada di -4 sampai 4
    plt.xlim(-4, 4)
    plt.ylim(-0.5, 0.5) 

    plt.title("HTB AI SPACE - READ FROM LEFT TO RIGHT")
    plt.axis('equal')
    plt.grid(True, alpha=0.1)
    
    # Jika teks masih kebalik atas-bawah, uncomment baris ini:
    # plt.gca().invert_yaxis()

    print("[+] Coba baca sekarang, pasti jauh lebih tegak dan jelas!")
    plt.show()

if __name__ == "__main__":
    solve()
