import argparse

def verif_entree_user() :
    #Creation de l'objet parser pour les entrees utilisateur
    parser = argparse.ArgumentParser(description='Validation de certificat')

    #Ajout des arguments
    parser.add_argument('--format', dest='format', type=str, choices=['DER', 'PEM'], help='Format du certificat (DER/PEM)', required=True)
    parser.add_argument('fichier', metavar='FICHIER', type=str, help='Chemin du certificat a verifier')

    #Analyser les arguments de ligne de commande
    args = parser.parse_args()

    #Enregistrer les arguments de ligne de commande
    format = args.format
    fichier = args.fichier

    if not fichier.endswith('.crt') :
        print("Le fichier n'est pas au format CRT")
        return

    print("Format du certificat : ", format)
    print("Chemin du certificat : ", fichier)


verif_entree_user()