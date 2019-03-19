#!/usr/bin/env bash

BLS="github.com\/jstuczyn\/amcl\/version3\/go\/amcl\/BLS381"
BN="github.com\/jstuczyn\/amcl\/version3\/go\/amcl\/BN254"

sc=""
tc=""

if [ $1 == "BLS" ] || [ $1 == "BLS381" ] || [ $1 == "bls" ] || [ $1 == "bls381" ]
then   
    sc=$BN
    tc=$BLS
elif [ $1 == "BN" ] || [ $1 == "BN254" ] || [ $1 == "bn" ] || [ $1 == "bn254" ]
then
    sc=$BLS
    tc=$BN
else 
    echo "Invalid curve"
    exit
fi

find ./client/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./common/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./constants/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./crypto/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./daemon/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./logger/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./nym/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./sampleclientmain/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./server/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./tendermint/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./testdata/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./ttp/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 
find ./worker/ -type f -exec sed -i -e "s/$sc/$tc/g" {} \; 