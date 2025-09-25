import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname="172.16.11.2", username='root', password='asd123!@')

sftp = ssh.open_sftp()
with sftp.file('/etc/suricata/rules/local.rules', 'w') as f:
    f.write('test\n')
sftp.close()

ssh.close()
