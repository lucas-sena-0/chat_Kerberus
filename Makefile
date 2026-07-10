# Atalhos para subir os servidores e clientes do chat_Kerberus.
# Uso rapido:
#   make as        -> sobe o Authentication Server (porta 9000)
#   make tgs       -> sobe o Ticket Granting Server (porta 9001)
#   make chat      -> sobe o servidor de chat (porta 5000)
#   make login     -> autentica no Kerberos e entra no chat (U=lucas por padrao)
#   make lucas     -> atalho: login como lucas / senha123
#   make alice     -> atalho: login como alice / alice123
#   make test      -> roda a suite pytest
#   make help      -> mostra este resumo

PY ?= python3

# Parametros do login (podem ser sobrescritos: make login U=alice P=alice123)
# Obs: usamos U/P em vez de USER/PASS porque USER e uma variavel de ambiente
# ja definida pelo shell e o Make a herdaria automaticamente.
U ?= lucas
P ?= senha123
ADDR ?= 127.0.0.1

.PHONY: help as tgs chat login lucas alice test kerberos-cli

help:
	@echo "Alvos disponiveis:"
	@echo "  make as       - Authentication Server (127.0.0.1:9000)"
	@echo "  make tgs      - Ticket Granting Server (127.0.0.1:9001)"
	@echo "  make chat     - Servidor de chat (127.0.0.1:5000)"
	@echo "  make login    - Fluxo Kerberos + chat  (U=$(U) P=$(P))"
	@echo "  make lucas    - Atalho: login como lucas / senha123"
	@echo "  make alice    - Atalho: login como alice / alice123"
	@echo "  make test     - Executa pytest"
	@echo ""
	@echo "Dica: abra 4 terminais e rode 'make as', 'make tgs', 'make chat' e 'make lucas'."

as:
	$(PY) -m auth.kerberos.as_server

tgs:
	$(PY) -m auth.kerberos.tgs_server

chat:
	$(PY) -m server.server

login:
	$(PY) -m client.login -u $(U) -p $(P) --client-address $(ADDR)

lucas:
	$(MAKE) login U=lucas P=senha123

alice:
	$(MAKE) login U=alice P=alice123

kerberos-cli:
	$(PY) -m auth.kerberos.kerberos_client --username $(U) --password $(P) --client-address $(ADDR)

test:
	$(PY) -m pytest
