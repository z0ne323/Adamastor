# Adamastor set up guide
## Installing the server
### Create the VM
1) Install the latest ubuntu server ISO on https://ubuntu.com/download/server
2) After getting the ISO, follow the installation process for this new VM on your favorite hypervisor. (Pick always default options for everything)

### Booting the VM - Installing Ubuntu Server
1) Launch the VM and when booting the ISO, select your language and keyboard layout
2) When asked what type of install you want, make sure you select the default `Ubuntu Server`.
3) For the network connections step just wait a little bit to make sure the VM is able to connect to your interface. When this is done you should see the button switch from `Continue without network` to `Done`
4) No proxy address needs to be set up
5) For `Configuring Ubuntu archive mirror` I decided to switch from `http://ca.archive.ubuntu.com/ubuntu/` to the original one, `http://archive.ubuntu.com/ubuntu/` (wait a little bit to make sure the mirror location pass all the tests)
6) When arriving at the `Guided Storage configuration` step, just hit `tab` five times to go straight to the `Done` button. When hitting it, you should get to `FILE SYSTEM SUMMARY` part, hit done again, confirm by switching from `No` to `Continue` when prompted and get to the next step.
7) On the `Profile setup` part, set your name, username and password to `luis`. Set the server's name to `adamastor`. When this is done, hit `Done` button and go to the next step 
8) When asked to `Upgrade to Ubuntu Pro` just hit `Continue` to skip.
9) On the `SSH Setup` part, hit space to check the `Install Openssh server` line, then hit tab twice to go on the `Done` button. 
10) Last step will be to skip the part of the `Featured Server Snaps`, to do so, just hit tab to go on the `Done` button and hit enter to start the install!
11) Go grab a tea or coffee while the server is installing on the VM, when it's done just hit the `Reboot Now` button and hit `ENTER` when asked, then you should be good to go :)

### Setting up the machine

First step is to use any SSH client you want to connect to your newly installed machine.

Once you're logged in as `luis`, get update from your sources list, upgrade your packages and remove packages that were automatically installed to satisfy dependencies for other packages that are now no longer needed. To do all of this just use this command (you'll be prompted for `luis` password but I'm pretty sure you know it, also if you're prompted to restart services go ahead and do it): 

`sudo apt update -y && sudo apt full-upgrade -y && sudo apt autoremove -y`

When this is done, start to read what's next...

#### 1 - Clearing history / Disabling Command History Log
This step will be extremly important to make sure we don't leak anything, you can do so by following these steps as `luis`:

1) First clear any previous history by doing `history -c`
1) Create a symbolic link from .bash_history to /dev/null like so: `ln -sf /dev/null ~/.bash_history`
3) Validate the previous command by doing: `ls -l ~/.bash_history`

When this is done, repeat the same process but this time as `root`, do `sudo su` from `luis` user and go to the root home foler (`cd`). As a side note, please don't forget to remove the `snap/` folder from `root` like so : `rm -rfv /root/snap`. When this is done repeat the three steps you followed above with `luis` but for `root` this time.

#### 2 - Removing sudo rights for `luis` and setting up password for `luis` and `root`
We will be removing sudo rights from `luis`, some file in his home directory and we will also set up new password for `luis` and `root`

1) Remove sudo rights from `luis` with this command as `root`: `deluser luis sudo`
2) Remove `.sudo_as_admin_successful` file like this still as `root`: `rm -fv /home/luis/.sudo_as_admin_successful`
3) Set this password for root (`4d4m45702w457h3f125723d734m0p324702`) using this command: `passwd` as `root`
4) Set this password for luis (`1u15c23473d4d4m45702`) using this command: `passwd` as `luis`.

#### 3 - Installing necessary packages - Making sure everything is up to date, upgraded and / or removed
To make everything work for this challenges, we will need to have a few packages installed, to do so follow the steps below:

1) As `root`, use this command to install the packages: `apt install apache2 php libapache2-mod-php gcc ncurses-hexedit -y`
2) After installing them do as `root`: `apt update -y && apt full-upgrade -y && apt autoremove -y` just to make sure we're all good on the package side.

#### 4 - Setting up the foothold challenge

1) As `root`, remove the `index.html` from `/var/www/html` and replace it with the one you'll find in `/foothold`.
2) You can move the `adamastor_logo.ico` and `bugs_bunny.png` also in `/var/www/html` (you can use `python` to transfer the file to the server)
3) As `root` and while still being in `/var/www/html` in the machine, create a new directory called like this: `mkdir /var/www/html/NoFuzzingAllowedRight`
4) When this is done, still as `root`, put all the files you'll find under `/foothold/NoFuzzingAllowedRight/` from this project in this new directory (`/var/www/html/NoFuzzingAllowedRight`).
5) After this, always as `root`, create in `/var/www/html` a directory called like this: `mkdir /var/www/html/Database_Administration` (to store the reverse shells people will upload)
6) When this is done, you'll need to go edit the `/etc/apache2/apache2.conf` file by adding this block after the existing `<Directory>` directives: 
    ```
    <Directory /var/www/html/Database_Administration>
            AllowOverride All
    </Directory>
    ```
7) As `root`, make sure to change the ownership of everything under `/var/www/html` to `www-data` (the user that apache run as). You can do this like that: `chown www-data:www-data /var/www/html/*`
8) Last thing of course is to reboot the service to incorporate the change. We can do so like this as `root`: `service apache2 restart`


#### 5 - Setting up the intermediary part (`ssh`)

1) As `root` do this command: `echo "[*] ssh password for luis => 1u15c23473d4d4m45702" > /t4k3_th1s_p4ssw0rd_l4st_34sy_th1ng_y0ull_s33_before_g01ng_NUTS.txt`
2) As `root`, do this command: `sed -i 's/^#* *PrintLastLog yes/PrintLastLog no/' /etc/ssh/sshd_config`, to remove the last login line when connecting with `ssh`
3) As `root` do this command: `sed -i 's/^#* *PrintMotd no/PrintMotd yes/' /etc/ssh/sshd_config`, to create a Message Of The Day
4) As `root` create a file like this: `touch /etc/motd` and then put this inside:
```
##################################################
#      .-``'.       BRACE !!!       .'''-.       #
#    .`   .` ~ A wave is coming... ~ `.   '.     #  
#_.-'     '._      - r0de0 -        _.'     '-._ #
##################################################
```
5) As `root`, do this command: `sed -i 's/^session    optional     pam_motd.so  motd=\/run\/motd.dynamic/# session    optional     pam_motd.so  motd=\/run\/motd.dynamic/' /etc/pam.d/sshd && sudo sed -i 's/^session    optional     pam_motd.so noupdate/# session    optional     pam_motd.so noupdate/' /etc/pam.d/sshd`, to remove the Welcome Message when connecting with `ssh`
6) As `root`, to apply the changes, do `service ssh restart`.

#### 6 - Setting up the intermediary part (`server.py`)

1) As `root`, if you find a new `snap/` folder, delete it like so: `rm -rfv /root/snap` 
2) As `root`, Put the file `server.py` from the folder `/privesc` in our project to `/root` on the machine
3) As `root`, edit your cronjob using this command: `crontab -e`, since it will be the first time running this command they might ask for which editor to use, press `1` if you got prompted about this. Then it should open your cronjobs, add at the end of the file this line: `@reboot /usr/bin/python3 /root/server.py`, this will allow the script to run at each bootup.
4) To start the cronjob, reboot using the command: `reboot` still as `root`

#### 7 - Setting up the privesc challenge

1) As `luis`, execute these commands: 
```
echo "export DATA_DETAILS_01=127.0.0.1" >> ~/.bashrc
echo "export DATA_DETAILS_02=888" >> ~/.bashrc
source ~/.bashrc
```
2) As `root`, move the file `adamastor.c` from the folder `/privesc` in our project to `/home/luis`.
3) As `root`, compile the project like so: `gcc adamastor.c -o adamastor` and then delete the source code file like this: `rm adamastor.c`
4) As `root`, set the `SUID` bit like this on the binary: `chmod +s adamastor`
5) The next step will be to execute this command as `root`: `hexeditor /home/luis/adamastor`, when you're in `hexeditor`, go to the 6th byte in the binary and change the value from `01` to `02`
6) After it's done, you can uninstall the package we used before like so as `root`: `apt purge gcc ncurses-hexedit -y && apt autoremove -y`
7) As `luis` execute this command: `echo "[*] NEVER FORGET: Things aren't always as they seem, even in the storm. Now, it's your time to reach Adamastor, the only thing left is to wish you a good luck in this adventure... :)" > README_BEFORE_STARTING.TXT`