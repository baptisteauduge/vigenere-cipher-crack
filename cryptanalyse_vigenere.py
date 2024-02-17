# Sorbonne Université 3I024 2023-2024
# TME 2 : Cryptanalyse du chiffre de Vigenere

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
freq_FR = [0.09213437454330574, 0.010354490059155806, 0.030178992381545422, 0.037536932666586184, 0.17174754258773295, 0.010939058717380115, 0.0106150043524949, 0.010717939268399616, 0.07507259453174145, 0.0038327371156619923, 6.989407870073262e-05, 0.06136827190067416, 0.026498751437594118, 0.07030835996721332, 0.04914062053233872, 0.023697905083841123, 0.010160057440224678, 0.06609311162084369, 0.07816826681746844, 0.0737433362349966, 0.06356167517044624, 0.016450524523290613, 1.1437212878301701e-05, 0.004071647784675406, 0.0023001505899695645, 0.0012263233808401269]
MAX_SIZE_KEY = 20
THRESHOLD_IC_KEY_SIZE = 0.06

# Chiffrement César
def chiffre_cesar(txt, key):
    """
    Function used to encrypt a text using the Caesar cipher
    :param txt: the text to encrypt
    :param key: the key used to encrypt the text (int)
    """
    res = ""
    for letter in txt:
        res += alphabet[(alphabet.index(letter) + key) % len(alphabet)]
    return res

# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    Function used to decrypt a text using the Caesar cipher
    :param txt: the text to decrypt
    :param key: the key used to decrypt the text (int)
    """
    res = ""
    for letter in txt:
        res += alphabet[(alphabet.index(letter) - key) % len(alphabet)]
    return res

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    Function used to encrypt a text using the Vigenere cipher
    :param txt: the text to encrypt
    :param key: the key used to encrypt the text (string)
    """
    # Cipher_i = (P_i + K_{i mod len(K)}) mod 26
    res = ""
    for i, letter in enumerate(txt):
        res += alphabet[(alphabet.index(letter) + key[i % len(key)]) % len(alphabet)]
    return res

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    Function used to decrypt a text using the Vigenere cipher
    :param txt: the text to decrypt
    :param key: the key used to decrypt the text (string)
    """
    # Plain_i = (C_i - K_{i mod len(K)}) mod 26
    res = ""
    for i, letter in enumerate(txt):
        res += alphabet[(alphabet.index(letter) - key[i % len(key)]) % len(alphabet)]
    return res

# Analyse de fréquences
def freq(txt):
    """
    Function used to calculate the occurences of each letter in a text and return the result as a list
    :param txt: the text to analyze !MUST BE UPPERCASE AND CONTAIN ONLY A-Z!
    """
    hist=[0.0]*len(alphabet)
    for c in txt:
        hist[alphabet.index(c)]+=1
    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    Function used to find the index (in the alphabet) of the most frequent letter in a text
    :param txt: the text to analyze !MUST BE UPPERCASE AND CONTAIN ONLY A-Z!
    """
    frequences_text = freq(txt)
    return frequences_text.index(max(frequences_text))

# indice de coïncidence
def indice_coincidence(hist):
    """
    Function used to calculate the index of coincidence of a text using occurrences of each letter
    """
    ic = 0
    sum = 0
    for i in range(len(hist)):
        ic += hist[i] * (hist[i] - 1)
        sum += hist[i]
    return ic / (sum * (sum - 1))

def _get_columns_with_key_length(cipher, key_length):
    splitted_cols = [[] for _ in range(key_length)]
    for idx_elem in range(len(cipher)):
        cipher_elem = cipher[idx_elem]
        splitted_cols[idx_elem % key_length].append(cipher_elem)
    return splitted_cols

# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    Function used to find the length of the key used to encrypt a text
    the function is based on the index of coincidence, and the threshold is set to
    THRESHOLD_IC_KEY_SIZE. If the mean index of coincidence is greater than the threshold,
    the function returns the key size, otherwise it returns 0.
    !The key size is limited to MAX_SIZE_KEY!
    :param cipher: the text to analyze
    """
    for key_size in range(1, MAX_SIZE_KEY + 1):
        splitted_cols = _get_columns_with_key_length(cipher, key_size)
        mean_ic = 0
        for col in splitted_cols:
            mean_ic += indice_coincidence(freq(col))
        mean_ic /= key_size
        if (mean_ic > THRESHOLD_IC_KEY_SIZE):
            return key_size
    return 0
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    Function used to find the key of a text using the most frequent letter of each column, 
    and the key length as parameters. The function returns the key as a list of integers
    that represent the shift to apply to each column.
    :param cipher: the text to analyze
    :param key_length: the length of the key
    """
    decalages=[0]*key_length
    splitted_cols_arr = _get_columns_with_key_length(cipher, key_length)
    splitted_cols_str = [''.join(col) for col in splitted_cols_arr]
    for i in range(key_length):
        idx_letter = lettre_freq_max(splitted_cols_str[i])
        decalages[i] = (idx_letter - alphabet.index('E')) % len(alphabet)
    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    Documentation à écrire
    """
    key_length = longueur_clef(cipher)
    assert key_length > 0, "Unable to find the key length"
    key = clef_par_decalages(cipher, key_length)
    return dechiffre_vigenere(cipher, key)

# Question 9 :
# On voit que la cryptanalyse nous permet de retrouver 18 textes en clair
# On pourrait expliquer ce faible taux de réussite par plusieurs facteurs :
# - Deja, il est possible que la longueur de la clé soit supérieur à 20, ce qui
#   rendrait la cryptanalyse impossible
# - Ensuite, la cryptanalyse est basée sur l'indice de coïncidence, qui est une
#   mesure statistique. Il est donc possible que le texte chiffré ne soit pas
#   assez long pour que l'indice de coïncidence soit significatif.
# - Enfin, il est possible que les textes soient particuliers et ne contiennent pas
#   certaines lettres, et notamment la lettre 'E' qui nous permet de déduire le décalage
#   de la clé.

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    Function used to calculate the mutual index of coincidence between two texts, the second text
    will be shifted by d before calculations.
    :param h1: the first text to analyze
    :param h2: the second text to analyze
    :param d: the shift to apply to the second text
    """
    res = 0
    sum1 = 0
    sum2 = 0
    assert len(h1) == len(h2), "The two occurrences array must have the same length"
    for i in range(len(h1)):
        res += h1[i]*h2[(i+d)%len(h2)]
        sum1 += h1[i]
        sum2 += h2[i]
    return res / (sum1*sum2)

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Function used to find the relative shift of each column of a text (compared to the first column)
    using the mutual index of coincidence. It will return the shifts as a list of integers.
    :param cipher: the text to analyze
    :param key_length: the length of the key
    """
    decalages=[0]*key_length
    splitted_cols_arr = _get_columns_with_key_length(cipher, key_length)
    splitted_cols_str = [''.join(col) for col in splitted_cols_arr]
    for i in range(key_length):
        max_icm = 0
        max_icm_idx = 0
        for d in range(len(alphabet)):
            icm = indice_coincidence_mutuelle(freq(splitted_cols_str[0]), freq(splitted_cols_str[i]), d)
            if icm > max_icm:
                max_icm = icm
                max_icm_idx = d
        decalages[i] = max_icm_idx
    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    Documentation à écrire
    """
    key_length = longueur_clef(cipher)
    assert key_length > 0, "Unable to find the key length"
    relative_shift_key = tableau_decalages_ICM(cipher, key_length)
    cesar_cipher = dechiffre_vigenere(cipher, relative_shift_key)
    idx_freq_max = lettre_freq_max(cesar_cipher)
    key = (idx_freq_max - alphabet.index('E')) % len(alphabet)
    return dechiffre_cesar(cesar_cipher, key)

# Question 12 :
# On voit que la cryptanalyse nous permet de retrouver 43 textes en clair
# On pourrait expliquer ce taux de réussite plus élevé par le fait que la
# cryptanalyse est basée sur l'indice de coïncidence mutuelle, qui est une
# mesure statistique plus précise que l'indice de coïncidence simple.
# En effet, l'indice de coïncidence mutuelle permet de comparer deux textes
# et de trouver le décalage qui maximise la coïncidence entre les deux textes.
# Cela permet de trouver le décalage de chaque colonne du texte chiffré par rapport
# à la première colonne, et donc de retrouver la clé de chiffrement.
# Cependant, on voit que la cryptanalyse ne permet pas de retrouver tous les textes
# en clair, ce qui peut s'expliquer par le fait que la longueur de la clé est supérieure
# à 20, ou que le texte chiffré est trop court pour que l'indice de coïncidence mutuelle
# soit significatif.



################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def _find_mean(L):
    assert len(L) > 0, "The list must not be empty"
    res = 0
    for elem in L:
        res += elem
    return res / len(L)

# ! Le premier test a été modifié car la fonction renvoyait une valeur de 
# ! corrélation de 0.9999999999998, et non 1.0, du fait de la précision des
# ! calculs en python.

def correlation(L1,L2):
    """
    Function used to calculate the correlation between two lists of the same size
    :param L1: the first list
    :param L2: the second list
    """
    assert len(L1) == len(L2), "The two lists must have the same length"
    mean_L1 = _find_mean(L1)
    mean_L2 = _find_mean(L2)
    sum_dist_L1 = 0
    sum_dist_L2 = 0
    sum_prod_dist = 0
    for i in range(len(L1)):
        sum_dist_L1 += (L1[i] - mean_L1)**2
        sum_dist_L2 += (L2[i] - mean_L2)**2
        sum_prod_dist += (L1[i] - mean_L1) * (L2[i] - mean_L2)
    sum_dist_L1 = math.sqrt(sum_dist_L1)
    sum_dist_L2 = math.sqrt(sum_dist_L2)
    assert sum_dist_L1 > 0 and sum_dist_L2 > 0, "Error: division by 0 in correlation calculation"
    return sum_prod_dist / (sum_dist_L1 * sum_dist_L2)

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    Documentation à écrire
    """
    key=[0]*key_length
    corr_values = [0]*key_length
    score = 0.0
    splitted_cols_arr = _get_columns_with_key_length(cipher, key_length)
    splitted_cols_str = [''.join(col) for col in splitted_cols_arr]
    for i in range(key_length):
        max_corr = 0
        max_corr_idx = 0
        for d in range(len(alphabet)):
            shifted_col = chiffre_cesar(splitted_cols_str[i], d)
            corr = correlation(freq_FR, freq(shifted_col))
            if corr > max_corr:
                max_corr = corr
                max_corr_idx = (len(alphabet) - d) % len(alphabet)
        key[i] = max_corr_idx
        corr_values[i] = max_corr
        score += max_corr
    score /= key_length
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    Documentation à écrire
    """
    max_corr = 0
    max_corr_key_length = 0
    max_corr_key = []
    for key_length in range(1, MAX_SIZE_KEY + 1):
        (score, key) = clef_correlations(cipher, key_length)
        if score > max_corr:
            max_corr = score
            max_corr_key_length = key_length
            max_corr_key = key
    return dechiffre_vigenere(cipher, max_corr_key)
    return "TODO"


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
    main(sys.argv[1:])
