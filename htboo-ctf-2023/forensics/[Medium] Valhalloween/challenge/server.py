from prettytable import PrettyTable
from secret import FLAG
import socketserver
import signal
import time

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Handler(socketserver.BaseRequestHandler):

    def handle(self):
        signal.alarm(0)
        main(self.request)


class ReusableTCPServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


def sendMessage(s, msg):
    s.send(msg.encode())


def receiveMessage(s, msg):
    sendMessage(s, msg)
    return s.recv(4096).decode().strip()



def main(s):

    questionnaire = {
'What are the IP address and port of the server from which the malicious actors downloaded the ransomware? (for example: 98.76.54.32:443)':'103.162.14.116:8888',
'According to the sysmon logs, what is the MD5 hash of the ransomware? (for example: 6ab0e507bcc2fad463959aa8be2d782f)':'b94f3ff666d9781cb69088658cd53772',
'Based on the hash found, determine the family label of the ransomware in the wild from online reports such as Virus Total, Hybrid Analysis, etc. (for example: wannacry)':'lokilocker',
'What is the name of the task scheduled by the ransomware? (for example: WindowsUpdater)':'Loki',
'What are the parent process name and ID of the ransomware process? (for example: svchost.exe_4953)':'powershell.exe_3856',
'Following the PPID, provide the file path of the initial stage in the infection chain. (for example: D:\\Data\\KCorp\\FirstStage.pdf)':'C:\\Users\\HoaGay\\Documents\\Subjects\\Unexpe.docx',
'When was the first file in the infection chain opened (in UTC)? (for example: 1975-04-30_12:34:56)':'2023-09-20_03:03:20'
}

    t = PrettyTable(['Title', 'Description'])
    t.add_row(['Valhalloween', 'As I was walking the neighbor\'s streets for some Trick-or-Treat,\na strange man approached me, saying he was dressed as "The God of Mischief!".\nHe handed me some candy and disappeared. Among the candy bars was a USB in disguise,\nand when I plugged it into my computer, all my files were corrupted!\nFirst, spawn the haunted Docker instance and connect to it!\nDig through the horrors that lie in the given Logs\nand answer whatever questions are asked of you!'])

    sendMessage(s,f'\n{t}\n\n')

    for question,answer in questionnaire.items():
    
        counter = 0
        threshold = 0   


        sendMessage(s,f'{bcolors.HEADER}{question}\n{bcolors.ENDC}')
        ans = receiveMessage(s,'> ')

        while ans.lower() != answer.lower():

            counter += 1

            sendMessage(s,f'{bcolors.FAIL}[-] Wrong Answer.\n')
            sendMessage(s,f'{bcolors.HEADER}{question}\n{bcolors.ENDC}')

            if counter % 3 == 0 and counter != 0:
                threshold += 30

                for i in range(threshold,0,-1):
                    sendMessage(s,f'Please wait {i} seconds.\r')
                    time.sleep(1)

            sendMessage(s,'\n')
            ans = receiveMessage(s,'> ')

        sendMessage(s,f'{bcolors.OKGREEN}[+] Correct!\n\n{bcolors.HEADER}')

    sendMessage(s,f'{bcolors.OKGREEN}[+] Here is the flag: {FLAG}\n')



if __name__ == '__main__':

    socketserver.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer(("0.0.0.0", 1337), Handler)
    server.serve_forever()