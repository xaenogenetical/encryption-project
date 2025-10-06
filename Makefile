encrypting: encrypt.cpp
	g++ encrypt.cpp -o e_alg
clean: e_alg
	rm -f e_alg