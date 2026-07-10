# Chat Kerberus

Projeto acadêmico em Python com fluxo Kerberos simplificado para autenticar o cliente antes de entrar no chat TCP.

## Requisitos

- Python 3.10+ (recomendado 3.12)
- internet na primeira execucao, para baixar as dependencias

O arquivo `run.py` cria e usa a `.venv` automaticamente. 
## Uso rapido

```bash
python run.py setup
python run.py as
python run.py tgs
python run.py chat
python run.py login
```

O comando `login` usa `lucas` / `senha123` por padrao. Para outro usuario:

```bash
python run.py login -u alice -p alice123
```

Se quiser executar as etapas separadamente:

```bash
python run.py kerberos -u lucas -p senha123
python run.py client -u lucas --ticket-v <TicketV> --kc-v <Kc_v_em_Base64>
```

## Como testar

```bash
python run.py test
```

## Comandos do chat

- Escreva qualquer texto para enviar uma mensagem.
- `/list` lista os usuarios online.
- `/quit` encerra a sessao.

## Estrutura principal

- `run.py`: launcher multiplataforma do projeto.
- `auth/kerberos/as_server.py`: servidor de autenticacao.
- `auth/kerberos/tgs_server.py`: servidor de concessao de tickets.
- `auth/kerberos/kerberos_client.py`: cliente que executa o fluxo Kerberos.
- `server/server.py`: servidor do chat.
- `client/client.py`: cliente do chat.
- `shared/protocol.py`: protocolo simples em JSON por linha.
- `tests/`: suite de testes automatizados.
