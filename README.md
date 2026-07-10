# Chat Kerberus

Projeto acadêmico em Python com fluxo Kerberos simplificado para autenticar o cliente antes de entrar no chat TCP.

## Requisitos

- Python 3.12+
- `cryptography`
- `pytest`

Se você estiver usando a virtualenv que já vem no repositório, ative-a antes de executar os comandos.

## Instalação rápida

```bash
python -m pip install cryptography pytest
```

## Como rodar cada parte

### 1. Authentication Server

```bash
python -m auth.kerberos.as_server --host 127.0.0.1 --port 9000
```

### 2. Ticket Granting Server

```bash
python -m auth.kerberos.tgs_server --host 127.0.0.1 --port 9001
```

### 3. Servidor de chat

```bash
python -m server.server --host 127.0.0.1 --port 5000
```

### 4. Fluxo Kerberos

O cliente Kerberos executa a etapa AS -> TGS usando usuário e senha válidos do arquivo `principals.json`.

Exemplos válidos atualmente:

- `lucas` / `senha123`
- `alice` / `alice123`

```bash
python -m auth.kerberos.kerberos_client --username lucas --password senha123 --client-address 127.0.0.1
```

Esse comando valida o fluxo Kerberos e prepara `TicketV` e `Kc_v` em memória. O cliente de chat abaixo espera esses dois valores para autenticar no servidor.

### 5. Cliente de chat

```bash
python -m client.client --host 127.0.0.1 --port 5000 -u lucas --ticket-v <TicketV> --kc-v <Kc_v_em_Base64>
```

## Como testar

Rodar a suíte completa:

```bash
python -m pytest
```

Rodar apenas testes específicos:

```bash
python -m pytest tests/test_kdf.py
python -m pytest tests/test_crypto.py tests/test_as_flow.py tests/test_tgs_flow.py
python -m pytest tests/test_service_auth.py tests/test_replay.py
```

## Comandos do chat

- Escreva qualquer texto para enviar uma mensagem.
- `/list` lista os usuários online.
- `/quit` encerra a sessão.

## Estrutura principal

- `auth/kerberos/as_server.py`: servidor de autenticação.
- `auth/kerberos/tgs_server.py`: servidor de concessão de tickets.
- `auth/kerberos/kerberos_client.py`: cliente que executa o fluxo Kerberos.
- `server/server.py`: servidor do chat.
- `client/client.py`: cliente do chat.
- `shared/protocol.py`: protocolo simples em JSON por linha.
- `tests/`: suíte de testes automatizados.
