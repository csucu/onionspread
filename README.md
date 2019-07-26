# OnionSpread
Load balancing for Tor hidden services.

Currently under development. Only supports v2 for now, but working on v3.

### Configuration:
The configuration file follows the following format:
```
{
  "Services" : [
    {
      "PrivateKeyPath": "key.pem",
      "BackendAddresses": ["7ctbljpgkiayaita","irthspr2nebf7x5i"]
    },
    {
      "PrivateKeyPath": "key2.pem",
      "BackendAddresses": ["nyrcu2p5o7nzw4jm","f7xybk44zlrlgz47"]
    }
  ],
  "ControlPortPassword": "password",
  "Address": "localhost:9055",
  "LogFilePath": ""
}
```
Each service represents a master hidden service that will balance the back instances specified in "BackendAddresses". “Address” represents the address of the control port onionspread will use as a controller. Both ControlPortPassword and LogFilePath fields are optional. 


### Building:
```
go build -o onionspread
```

### Running:
```
./onionspread -d -c config.json
```

### Todo:
* v3 balancing
* More testing
* General code clean up
