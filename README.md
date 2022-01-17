
```
___________
                   /.---------.\`-._
                  //          ||    `-._
                  || `-._     ||        `-._
                  ||     `-._ ||            `-._
                  ||    _____ ||`-._            \
            _..._ ||   | __ ! ||    `-._        |
          _/     \||   .'  |~~||        `-._    |
      .-``     _.`||  /   _|~~||    .----.  `-._|
     |      _.`  _||  |  |23| ||   / :::: \    \
     \ _.--`  _.` ||  |  |56| ||  / ::::: |    |
      |   _.-`  _.||  |  |79| ||  |   _..-'   /
      _\-`   _.`O ||  |  |_   ||  |::|        |
    .`    _.`O `._||  \    |  ||  |::|        |
 .-`   _.` `._.'  ||   '.__|--||  |::|        \
`-._.-` \`-._     ||   | ":  !||  |  '-.._    |
         \   `--._||   |_:"___||  | ::::: |   |
          \  /\   ||     ":":"||   \ :::: |   |
           \(  `-.||       .- ||    `.___/    /
           |    | ||   _.-    ||              |
           |    / \.-________\____.....-----'
           \    -.      \ |         |
            \     `.     \ \        |
 __________  `.    .'\    \|        |\  _________
    SeeYouCM   `..'   \    |        | \   Thief
                \   .'    |       /  .`.
                | \.'      |       |.'   `-._
                 \     _ . /       \_\-._____)
                  \_.-`  .`'._____.'`.
                    \_\-|             |
                         `._________.'
```
# SeeYouCM Thief

Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials

## Usage

Sometimes the CUCM server supplys a list of hostnames. Without specifying a phone IP address the script will attempt to
download every config in the listing.

`./thief.py -H <Cisco CUCM Server> [--verbose]`

OR 

if that doesnt work try using the --phone setting which will parse the web interface for the CUCM address and will do a reverse lookup for other phones in the same subnet.

`./thief.py --phone <Cisco IP Phoner> [--verbose]`

OR

if that doesnt work you can specify a subnet to scan with reverse lookups using 
 
`./thief.py --subnet <subnet to scan> [--verbose]`

## Setup
`python3 -m pip install -r requirements.txt`

## Docker
`docker build . -t name thief:latest`

`docker run thief:latest`
