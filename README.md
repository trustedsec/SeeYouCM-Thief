
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

Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials. Will also optionally enumerate active directory users from the UDS API. 


## Blog 
https://www.trustedsec.com/blog/seeyoucm-thief-exploiting-common-misconfigurations-in-cisco-phone-systems/

## Usage

Sometimes the CUCM server supplies a list of hostnames. Without specifying a phone IP address the script will attempt to
download every config in the listing.

`./thief.py -H <Cisco CUCM Server> [--verbose]`

OR 

if that doesnt work try using the --phone setting which will parse the web interface for the CUCM address and will do a reverse lookup for other phones in the same subnet.

`./thief.py --phone <Cisco IP Phoner> [--verbose]`

OR

if that doesnt work you can specify a subnet to scan with reverse lookups using 
 
`./thief.py --subnet <subnet to scan> [--verbose]`

### User Enumeration
To optionally enumerate Active Directory users from the UDS api on the CUCM add `--userenum` and it will automatically bruteforce through the API aa-zz to return a list of users.

`./thief.py -H <CUCM server> --userenum`

## Setup
`python3 -m pip install -r requirements.txt`

## Docker
`docker build . -t name thief:latest`

`docker run thief:latest`
