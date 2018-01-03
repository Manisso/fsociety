#!/bin/bash
clear
echo "
███╗   ███╗ █████╗ ███╗   ██╗██╗███████╗███████╗ ██████╗
████╗ ████║██╔══██╗████╗  ██║██║██╔════╝██╔════╝██╔═══██╗
██╔████╔██║███████║██╔██╗ ██║██║███████╗███████╗██║   ██║
██║╚██╔╝██║██╔══██║██║╚██╗██║██║╚════██║╚════██║██║   ██║
██║ ╚═╝ ██║██║  ██║██║ ╚████║██║███████║███████║╚██████╔╝
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝╚══════╝ ╚═════╝
▀▀█▀▀ █▀▀█ █▀▀█ █   █▀▀ ~ Tools Instaler By Ⓜ Ⓐ Ⓝ Ⓘ Ⓢ Ⓢ Ⓞ  ☪ ~
  █   █  █ █  █ █   ▀▀█
  ▀   ▀▀▀▀ ▀▀▀▀ ▀▀▀ ▀▀▀

";

if [ $PREFIX = "/data/data/com.termux/files/usr"]; then
    INSTALL_DIR=$PREFIX/usr/share/doc/fsociety
    BIN_DIR=$PREFIX/usr/bin/
    pkg install -y git python2
else
    INSTALL_DIR=/usr/share/doc/fsociety
    BIN_DIR=/usr/bin/
fi

echo "[✔] Checking directories...";
if [ -d $INSTALL_DIR ]; then
    echo "[◉] A directory fsociety was found! Do you want to replace it? [Y/n]:" ;
    read mama
    if [ $mama == "y" ]; then
        rm -R $INSTALL_DIR
    else
        exit
    fi
fi

echo "[✔] Installing ...";
echo "";
git clone https://github.com/Manisso/fsociety $INSTALL_DIR;
echo "#!/bin/bash
python $INSTALL_DIR/fsociety.py" '${1+"$@"}' > fsociety;
chmod +x fsociety;
sudo cp fsociety /usr/bin/;
rm fsociety;


if [ -d $INSTALL_DIR ] ;
then
    echo "";
    echo "[✔] Tool istalled with success![✔]";
    echo "";
    echo "[✔]====================================================================[✔]";
    echo "[✔] ✔✔✔  All is done!! You can execute tool by typing fsociety !   ✔✔✔ [✔]";
    echo "[✔]====================================================================[✔]";
    echo "";
else
    echo "[✘] Installation failed![✘] ";
    exit
fi
