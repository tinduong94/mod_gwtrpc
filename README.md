# mod_gwtrpc
mod_gwtrpc is an extension for ModSecurity to allow GWT-RPC payload parsing.

Since GWT-RPC payload is a serialization of Java objects, mod_gwtrpc can not (and don't need to) reconstruct these objects in C. 

mod_gwtrpc assumes that all values do not match to data-type format are user input values and pass these values to ModSecurity.

For example :

`7|2|7|https://127.0.01/resources/main/|F80836E7FF9D63BB4AF4AF3CF7858ACE|com.mytest.gwt.client.core.client.data.RpcTokenDtsc/1025630141|com.mytest.test.share.common.shared.service.UtilsRpcQueryService|method_name|java.lang.String/2004016611|arg_value|1|2|3|0|0|0|4|5|1|6|7|`

The payload passes to ModSecurity is:

`args[]=com.mytest.test.share.common.shared.service.UtilsRpcQueryService&args[]=method_name&args[]=arg_value`

Only GWT-RPC v7 is tested. You can modify the code yourself in order to make it work well with other versions of GWT-RPC.


# Building
If you do not have apxs installed, install it first.

Compile as a normal user:

`apxs -I <ModSecurity_source_path> -I /usr/include/libxml2 -ca mod_gwtrpc.c`

Install as a super user:

`sudo apxs -i mod_gwtrpc.la`

# Using the module

Once mod_gwtrpc is built and installed, you can load it like any other Apache module, but it must be loaded after the mod_security2.so module:

```
#Load mod_security module

LoadModule security2_module modules/mod_security2.so

#Load mod_gwtrpc module

LoadModule gwtrpc_parser_module modules/mod_gwtrpc.so
```

Write a phase 1 rule to set the parser:

`SecRule REQUEST_HEADERS:Content-Type "gwt/x-gwt-rpc?" "id:'1994',phase:1,pass,nolog,ctl:requestBodyProcessor=GWTRPC"`

Any request that matches GWT-RPC content-type will be processed by mod_gwtrpc.

# Contact
Feel free to open an issue here for any problems.

Thanks !
