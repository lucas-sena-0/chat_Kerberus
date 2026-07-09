# Chat Kerberus

Chat cliente-servidor em Python com socket TCP e threading, preparado para futura integração com Kerberos.

## Requisitos

- Python 3.12+
- Nenhuma dependência externa

## Executando o servidor

```bash
python -m server.server --host 127.0.0.1 --port 5000
```

## Executando o cliente

Use um dos usuarios padrão configurados no servidor:

- `alice` / `alice123`
- `bob` / `bob123`
- `carol` / `carol123`

```bash
python -m client.client --host 127.0.0.1 --port 5000 --username alice --password alice123
```

## Comandos do chat

- Escreva qualquer texto para enviar uma mensagem.
- `/users` lista os usuarios online.
- `/quit` encerra a sessão.

## Arquitetura

- `shared/protocol.py`: protocolo simples em JSON por linha.
- `auth/simple_auth.py`: autenticação substituível.
- `server/session.py`: ciclo de vida de cada conexão.
- `server/server.py`: accept loop, broadcast e gestão de sessões.
- `server/users.py`: credenciais padrão e registro de usuários online.
- `client/client.py`: cliente CLI com envio e recebimento concorrentes.
