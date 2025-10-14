### CryptoPython

Fichiers python permettant de réaliser du chiffrement AES et RSA ainsi que du hachage SHA. 

Objectif : comprendre son fonctionnement, commenter et réaliser un programme de test....




mkdir actions-runner && cd actions-runner

curl -o actions-runner-linux-x64-2.328.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.328.0/actions-runner-linux-x64-2.328.0.tar.gz

echo "01066fad3a2893e63e6ca880ae3a1fad5bf9329d60e77ee15f2b97c148c3cd4e  actions-runner-linux-x64-2.328.0.tar.gz" | shasum -a 256 -c

tar xzf ./actions-runner-linux-x64-2.328.0.tar.gz

./config.sh --url https://github.com/ABA-ArThUr/cryptoPython --token BLQPCRPX5KLYJAUYLNEMX33I5ZJ52

./run.sh
