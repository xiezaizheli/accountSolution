using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using Neo.SmartContract.Framework.Services.System;
using Helper = Neo.SmartContract.Framework.Helper;
using System.ComponentModel;
using System.Numerics;
using System;

namespace Account
{
    public class Account : SmartContract
    {
        /** Operation of account records
        * addr,name,type,operated*/
        [DisplayName("accOperator")]   
        public static event deleAccOperated AccoutOperated;
        public delegate void deleAccOperated(byte[] from, byte[] name,BigInteger optype, BigInteger value);

        /** Operation of account approve records*/
        [DisplayName("accApproveOperator")]
        public static event approveOperated Approved;
        public delegate void approveOperated(byte[] from, byte[] to,byte[] srcName,byte[] destName,byte[] type,byte[] assetType,byte[] asset,BigInteger mount);

        /** Operation of account transfer records*/
        [DisplayName("accUserTransfer")]
        public static event userTransfer Transfered;
        public delegate void userTransfer(byte[] from, byte[] to, byte[] srcName, byte[] destName,byte[] assetType, byte[] asset, BigInteger mount);


        public delegate object NEP5Contract(string method, object[] args);

        //Default multiple signature committee account
        private static readonly byte[] committee = Helper.ToScriptHash("AZ77FiX7i9mRUPF2RyuJD2L8kS6UDnQ9Y7");

        //system account
        private const string SDS_ACCOUNT = "sds_account";
        private const string BU_ACCOUNT = "business_account";
        private const string ADMIN_ACCOUNT = "admin_account";
        private const string LOCK_GLOBAL = "lockGlobal";
        private const string ASSET_NEP5 = "nep5";
        private const string ASSET_NEP55 = "nep55";
        private const string APPROVE_TOTAL = "1";
        private const string APPROVE_SINGLE = "2";

        //StorageMap accountInfo, key: username
        //StorageMap nameInfo, key: addr
        //StorageMap asset, key: assetType
        //StorageMap nep5AssetStore, key: addr+nep5+assetName
        //StorageMap nep55AssetStore, key: addr+nep55+assetName
        //StorageMap global, key: str
        //StorageMap addrConfig,key:addr+type

        //Transaction type
        public enum ConfigTranType
        {
            TRANSACTION_TYPE_OPEN = 1,
            TRANSACTION_TYPE_LOCK,
            TRANSACTION_TYPE_WITHDRAW,
            TRANSACTION_TYPE_SHUT
        }

        public static object Main(string method, object[] args)
        {
            if (Runtime.Trigger == TriggerType.Verification)
            {
                return false;
            }
            else if (Runtime.Trigger == TriggerType.Application)
            {
                var callscript = ExecutionEngine.CallingScriptHash;

                if (method == "openAccount") return OpenAccount((byte[])args[0],(string)args[1]);

                if (method == "getAccountInfo") return GetAccountInfo((string)args[0]);

                if (method == "recharge") return Recharge((byte[])args[0], (string)args[1], (string)args[2], (string)args[3], (BigInteger)args[4]);

                if (method == "withdraw") return Withdraw((byte[])args[0], (string)args[1], (string)args[2], (string)args[3], (BigInteger)args[4]);

                if (method == "getBalance") return GetBalance((string)args[0], (string)args[1], (string)args[2]);

                if (method == "approveTransfer") return ApproveTransfer((byte[])args[0], (string)args[1], (string)args[2], (string)args[3], (string)args[4], (string)args[5],(BigInteger)args[6]);

                if (method == "getApproveInfo") return GetApproveInfo((string)args[0], (string)args[1], (string)args[2], (string)args[3], (string)args[4]);

                if (method == "userTransfer") return UserTransfer((byte[])args[0], (string)args[1], (string)args[2],(string)args[3], (string)args[4], (BigInteger)args[5]);

                //set account
                if (method == "setAccount") return SetAccount((string)args[0], (byte[])args[1]);

                if (method == "getAccount") return GetAccount((string)args[0]);

                if (method == "getUserName") return GetUserName((byte[])args[0]);


            }
            return false;
        }


        [DisplayName("openAccount")]
        public static bool OpenAccount(byte[] addr,string username)
        {
            if (!Runtime.CheckWitness(addr)) return false;

            if(!checkName(addr,username))
                throw new InvalidOperationException("The username is invalid.");

            StorageMap accountInfo = Storage.CurrentContext.CreateMap(nameof(accountInfo));
            byte[] account = accountInfo.Get(username);
            if(account.Length>0)
                throw new InvalidOperationException("The account is not null.");

            var txid = ((Transaction)ExecutionEngine.ScriptContainer).Hash;

            var openHeight = Blockchain.GetHeight();
            var nowtime = Blockchain.GetHeader(openHeight).Timestamp;

            AccountInfo info = new AccountInfo();
            info.owner = addr;
            info.txid = txid;
            info.openTime = nowtime;
            info.openHeight = openHeight;
            info.userName = username;
            accountInfo.Put(username, Helper.Serialize(info));

            StorageMap nameInfo = Storage.CurrentContext.CreateMap(nameof(nameInfo));
            nameInfo.Put(addr,username);
            //notify
            AccoutOperated(addr, username.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_OPEN, 0);
            return true;
        }

        [DisplayName("getAccountInfo")]
        public static AccountInfo GetAccountInfo(string username)
        {
            if (username.Length <=0)
                throw new InvalidOperationException("The parameter username SHOULD be longer than 0.");

            StorageMap accountInfo = Storage.CurrentContext.CreateMap(nameof(accountInfo));
            var result = accountInfo.Get(username); 
            if (result.Length == 0) return null;
            return Helper.Deserialize(result) as AccountInfo;
        }

        [DisplayName("getUserName")]
        public static string GetUserName(byte[] addr)
        {
            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            StorageMap nameInfo = Storage.CurrentContext.CreateMap(nameof(nameInfo));
            return nameInfo.Get(addr).AsString();
        }



        /// <summary>
        /// User rechanges asset to contract.
        /// </summary>
        /// <param name="addr">user address</param>
        /// <param name="username">account name,it's unique</param>
        /// <param name="type">nep5 or nep55</param>
        /// <param name="assetName">nep5:sds_account/nep55:SD-HELLO</param>
        /// <param name="mount">recharge mount</param>
        /// <returns>boolean</returns>
        [DisplayName("recharge")]
        public static Boolean Recharge(byte[] addr,string username,string type,string assetName,BigInteger mount)
        {
            if (!Runtime.CheckWitness(addr)) return false;

            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            if (type.Length <= 0)
                throw new InvalidOperationException("The parameter type SHOULD be longer than 0.");

            if (mount <= 0)
                throw new InvalidOperationException("The parameter lockMount MUST be greater than 0.");

            StorageMap accountInfo = Storage.CurrentContext.CreateMap(nameof(accountInfo));
            var result = accountInfo.Get(username);

            if (result.Length == 0)
                throw new InvalidOperationException("The accountInfo can not be null.");

            AccountInfo info =  Helper.Deserialize(result) as AccountInfo;
            if(info.owner != addr)
                throw new InvalidOperationException("The accountInfo is not self.");

            //不同的资产充值流程不一样
            if (type == ASSET_NEP5)
            {
                StorageMap asset = Storage.CurrentContext.CreateMap(nameof(asset));
                byte[] nep5AssetID = asset.Get(assetName);
                //current contract
                byte[] to = ExecutionEngine.ExecutingScriptHash;
                if (to.Length == 0)
                    throw new InvalidOperationException("The parameter to SHOULD be greater than 0.");

                object[] arg = new object[3];
                arg[0] = addr;
                arg[1] = to;
                arg[2] = mount;

                var AssetContract = (NEP5Contract)nep5AssetID.ToDelegate();

                if (!(bool)AssetContract("transfer", arg))
                    throw new InvalidOperationException("The operation is exception.");

                StorageMap nep5AssetStore = Storage.CurrentContext.CreateMap(nameof(nep5AssetStore));
                byte[] key = concatKey(concatKey(addr, ASSET_NEP5), assetName);
                BigInteger nep5Locked = nep5AssetStore.Get(key).AsBigInteger();
                nep5AssetStore.Put(key,nep5Locked+mount);
                //notify
                AccoutOperated(addr, assetName.AsByteArray(),(int)ConfigTranType.TRANSACTION_TYPE_LOCK, mount);
            }else if(type == ASSET_NEP55)
            {
                StorageMap asset = Storage.CurrentContext.CreateMap(nameof(asset));
                byte[] nep55AssetID = asset.Get(BU_ACCOUNT);
                //current contract
                byte[] to = ExecutionEngine.ExecutingScriptHash;
                if (to.Length == 0)
                    throw new InvalidOperationException("The parameter to SHOULD be greater than 0.");

                object[] arg = new object[4];
                arg[0] = assetName;
                arg[1] = addr;
                arg[2] = to;
                arg[3] = mount;

                var AssetContract = (NEP5Contract)nep55AssetID.ToDelegate();

                if (!(bool)AssetContract("transfer", arg))
                    throw new InvalidOperationException("The operation is exception.");

                StorageMap nep55AssetStore = Storage.CurrentContext.CreateMap(nameof(nep55AssetStore));
                byte[] key = concatKey(concatKey(addr, ASSET_NEP55), assetName);
                BigInteger nep55Locked = nep55AssetStore.Get(key).AsBigInteger();
                nep55AssetStore.Put(key, nep55Locked + mount);
                //notify
                AccoutOperated(addr, assetName.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_LOCK, mount);
            }
            return true;
        }

        /// <summary>
        /// User withdraw asset from contract.
        /// </summary>
        /// <param name="addr">user address</param>
        /// <param name="username">account name,it's unique</param>
        /// <param name="type">nep5 or nep55</param>
        /// <param name="assetName">nep5:sds_account/nep55:SD-HELLO</param>
        /// <param name="mount">recharge mount</param>
        /// <returns>boolean</returns>
        [DisplayName("withdraw")]
        public static Boolean Withdraw(byte[] addr, string username, string type, string assetName, BigInteger mount)
        {
            if (!Runtime.CheckWitness(addr)) return false;

            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            if (type.Length <= 0)
                throw new InvalidOperationException("The parameter type SHOULD be longer than 0.");

            if (mount <= 0)
                throw new InvalidOperationException("The parameter lockMount MUST be greater than 0.");

            StorageMap accountInfo = Storage.CurrentContext.CreateMap(nameof(accountInfo));
            var result = accountInfo.Get(username);
            if (result.Length == 0)
                throw new InvalidOperationException("The accountInfo can not be null.");

            AccountInfo info = Helper.Deserialize(result) as AccountInfo;
            if (info.owner != addr)
                throw new InvalidOperationException("The accountInfo is not self.");

            byte[] from = ExecutionEngine.ExecutingScriptHash;
            if (type == ASSET_NEP5)
            {
                //check nep5 asset
                StorageMap nep5AssetStore = Storage.CurrentContext.CreateMap(nameof(nep5AssetStore));
                byte[] key = concatKey(concatKey(addr, ASSET_NEP5), assetName);
                BigInteger nep5Locked = nep5AssetStore.Get(key).AsBigInteger();
                if (mount > nep5Locked)
                    throw new InvalidOperationException("The withdraw mount can not be larger than current.");

                StorageMap asset = Storage.CurrentContext.CreateMap(nameof(asset));
                byte[] nep5AssetID = asset.Get(assetName);
                object[] arg = new object[3];
                arg[0] = from;
                arg[1] = addr;
                arg[2] = mount;
                var nep5Contract = (NEP5Contract)nep5AssetID.ToDelegate();
                if (assetName == SDS_ACCOUNT)
                {
                    if (!(bool)nep5Contract("transfer_contract", arg))
                        throw new InvalidOperationException("The operation is error.");
                }
                else {
                    if (!(bool)nep5Contract("transfer", arg))
                        throw new InvalidOperationException("The operation is error.");
                }
                nep5AssetStore.Put(key, nep5Locked - mount);
                //notify
                AccoutOperated(addr, assetName.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_WITHDRAW, mount);
            }
            else if (type == ASSET_NEP55)
            {
                //check nep55 asset
                StorageMap nep55AssetStore = Storage.CurrentContext.CreateMap(nameof(nep55AssetStore));
                byte[] key = concatKey(concatKey(addr, ASSET_NEP55), assetName);
                BigInteger nep55Locked = nep55AssetStore.Get(key).AsBigInteger();
                if (mount > nep55Locked)
                    throw new InvalidOperationException("The withdraw mount can not be larger than current.");

                StorageMap asset = Storage.CurrentContext.CreateMap(nameof(asset));
                byte[] nep5AssetID = asset.Get(BU_ACCOUNT);
                object[] arg = new object[4];
                arg[0] = assetName;
                arg[1] = from;
                arg[2] = addr;
                arg[3] = mount;
                var nep5Contract = (NEP5Contract)nep5AssetID.ToDelegate();

                if (!(bool)nep5Contract("transfer", arg))
                    throw new InvalidOperationException("The operation is error.");

                nep55AssetStore.Put(key, nep55Locked - mount);
                //notify
                AccoutOperated(addr, assetName.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_WITHDRAW, mount);
            }
            return true;
        }

        /// <summary>
        /// User approve other account transfer mount.
        /// </summary>
        /// <param name="addr">user address</param>
        /// <param name="srcName">account name,it's unique</param> 
        /// <param name="destName">account name,it's unique</param>
        /// <param name="type">1/total or 2/single</param>
        /// <param name="assetType">nep5 or nep55</param>
        /// <param name="asset">nep5:sds_account/nep55:SD-HELLO</param>
        /// <param name="mount">approve mount</param>
        /// <returns>boolean</returns>
        [DisplayName("approveTransfer")]
        public static bool ApproveTransfer(byte[] addr, string srcName,string destName, string type, string assetType, string asset, BigInteger mount)
        {
            if (!Runtime.CheckWitness(addr)) return false;

            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            if (srcName.Length <= 0)
                throw new InvalidOperationException("The parameter srcName SHOULD be longer than 0.");

            if (destName.Length <= 0)
                throw new InvalidOperationException("The parameter destName SHOULD be longer than 0.");

            if (mount <= 0)
                throw new InvalidOperationException("The parameter lockMount MUST be greater than 0.");

            StorageMap accountInfo = Storage.CurrentContext.CreateMap(nameof(accountInfo));
            var result = accountInfo.Get(srcName);
            if (result.Length == 0)
                throw new InvalidOperationException("The accountInfo can not be null.");

            AccountInfo info = Helper.Deserialize(result) as AccountInfo;
            if (info.owner != addr)
                throw new InvalidOperationException("The accountInfo is not self.");

            var destResult = accountInfo.Get(destName);
            if (destResult.Length == 0)
                throw new InvalidOperationException("The accountInfo can not be null.");
            AccountInfo destInfo = Helper.Deserialize(destResult) as AccountInfo;
            byte[] destAddr = destInfo.owner;

            byte[] key = addr.Concat(destAddr).Concat(type.AsByteArray()).Concat(assetType.AsByteArray()).Concat(asset.AsByteArray());
            //total
            if (type == APPROVE_TOTAL)
            {
                StorageMap authTotal = Storage.CurrentContext.CreateMap(nameof(authTotal));
                authTotal.Put(key, mount);
            }
            //single
            else if (type == APPROVE_SINGLE)
            {
                StorageMap authSingle = Storage.CurrentContext.CreateMap(nameof(authSingle));
                authSingle.Put(key, mount);
            }
            Approved(addr,destAddr,srcName.AsByteArray(),destName.AsByteArray(),type.AsByteArray(),assetType.AsByteArray(),asset.AsByteArray(),mount);
            return true;
        }

        /// <summary>
        /// User get approve info.
        /// </summary>
        /// <param name="srcName">account name,it's unique</param> 
        /// <param name="destName">account name,it's unique</param>
        /// <param name="type">1/total or 2/single</param>
        /// <param name="assetType">nep5 or nep55</param>
        /// <param name="asset">nep5:sds_account/nep55:SD-HELLO</param>
        /// <returns>BigInteger</returns>
        [DisplayName("getApproveInfo")]
        public static BigInteger GetApproveInfo(string srcName, string destName, string type, string assetType, string asset)
        {
            if (srcName.Length <= 0)
                throw new InvalidOperationException("The parameter srcName SHOULD be longer than 0.");

            if (destName.Length <= 0)
                throw new InvalidOperationException("The parameter destName SHOULD be longer than 0.");

            StorageMap accountInfo = Storage.CurrentContext.CreateMap(nameof(accountInfo));
            var result = accountInfo.Get(srcName);
            if (result.Length == 0)
                throw new InvalidOperationException("The accountInfo can not be null.");

            AccountInfo info = Helper.Deserialize(result) as AccountInfo;
            byte[] srcAddr = info.owner;

            var destResult = accountInfo.Get(destName);
            if (destResult.Length == 0)
                throw new InvalidOperationException("The accountInfo can not be null.");
            AccountInfo destInfo = Helper.Deserialize(destResult) as AccountInfo;
            byte[] destAddr = destInfo.owner;

            BigInteger ret = 0;
            byte[] key = srcAddr.Concat(destAddr).Concat(type.AsByteArray()).Concat(assetType.AsByteArray()).Concat(asset.AsByteArray());
            //total
            if (type == APPROVE_TOTAL)
            {
                StorageMap authTotal = Storage.CurrentContext.CreateMap(nameof(authTotal));
                ret = authTotal.Get(key).AsBigInteger();
            }
            //single
            else if (type == APPROVE_SINGLE)
            {
                StorageMap authSingle = Storage.CurrentContext.CreateMap(nameof(authSingle));
                ret = authSingle.Get(key).AsBigInteger();
            }
            return ret;
        }

        /// <summary>
        /// User transfer asset.
        /// </summary>
        /// <param name="addr">other user address</param>
        /// <param name="srcName">account name,it's unique</param> 
        /// <param name="destName">account name,it's unique</param>
        /// <param name="assetType">nep5 or nep55</param>
        /// <param name="assetName">nep5:sds_account/nep55:SD-HELLO</param>
        /// <param name="mount">transfer mount</param>
        /// <returns>boolean</returns>
        [DisplayName("userTransfer")]
        public static bool UserTransfer(byte[] addr, string srcName, string destName,string assetType, string assetName, BigInteger mount)
        {
            if (!Runtime.CheckWitness(addr)) return false;

            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            if (srcName.Length <= 0)
                throw new InvalidOperationException("The parameter srcName SHOULD be longer than 0.");

            if (destName.Length <= 0)
                throw new InvalidOperationException("The parameter destName SHOULD be longer than 0.");

            if (mount <= 0)
                throw new InvalidOperationException("The parameter lockMount MUST be greater than 0.");

            if(srcName == destName)
                throw new InvalidOperationException("The parameter username MUST not be equal.");

            StorageMap accountInfo = Storage.CurrentContext.CreateMap(nameof(accountInfo));
            var result = accountInfo.Get(srcName);
            if (result.Length == 0)
                throw new InvalidOperationException("The accountInfo can not be null.");

            AccountInfo info = Helper.Deserialize(result) as AccountInfo;
            byte[] srcAddr = info.owner;

            var destResult = accountInfo.Get(destName);
            if (destResult.Length == 0)
                throw new InvalidOperationException("The accountInfo can not be null.");

            AccountInfo destInfo = Helper.Deserialize(destResult) as AccountInfo;
            byte[] destAddr = destInfo.owner;
            if(destAddr != addr)
                    throw new InvalidOperationException("The accountInfo is not self.");

            if(srcAddr == destAddr)
                    throw new InvalidOperationException("The address can not be equal.");

            byte[] keyTotal = srcAddr.Concat(destAddr).Concat(APPROVE_TOTAL.AsByteArray()).Concat(assetType.AsByteArray()).Concat(assetName.AsByteArray());
            byte[] keySingle = srcAddr.Concat(destAddr).Concat(APPROVE_SINGLE.AsByteArray()).Concat(assetType.AsByteArray()).Concat(assetName.AsByteArray());

            StorageMap authTotal = Storage.CurrentContext.CreateMap(nameof(authTotal));
            StorageMap authSingle = Storage.CurrentContext.CreateMap(nameof(authSingle));

            BigInteger total = authTotal.Get(keyTotal).AsBigInteger();
            if(total<mount)
                throw new InvalidOperationException("The mount can not be larger than total.");

            BigInteger single = authSingle.Get(keySingle).AsBigInteger();
            if (single < mount)
                throw new InvalidOperationException("The mount can not be larger than single.");

            byte[] from = ExecutionEngine.ExecutingScriptHash;
            if (assetType == ASSET_NEP5)
            {
                //check nep5 asset
                StorageMap nep5AssetStore = Storage.CurrentContext.CreateMap(nameof(nep5AssetStore));
                byte[] key = concatKey(concatKey(srcAddr, ASSET_NEP5), assetName);
                BigInteger nep5Locked = nep5AssetStore.Get(key).AsBigInteger();
                if (mount > nep5Locked)
                    throw new InvalidOperationException("The transfer mount can not be larger than current.");

                byte[] keyDest = concatKey(concatKey(destAddr, ASSET_NEP5), assetName);
                BigInteger destLocked = nep5AssetStore.Get(keyDest).AsBigInteger();
               
                nep5AssetStore.Put(key, nep5Locked - mount);
                nep5AssetStore.Put(keyDest, destLocked + mount);
                Transfered(srcAddr,destAddr,srcName.AsByteArray(),destName.AsByteArray(),assetType.AsByteArray(),assetName.AsByteArray(),mount);
            }
            else if (assetType == ASSET_NEP55)
            {
                //check nep55 asset
                StorageMap nep55AssetStore = Storage.CurrentContext.CreateMap(nameof(nep55AssetStore));
                byte[] key = concatKey(concatKey(srcAddr, ASSET_NEP55), assetName);
                BigInteger nep55Locked = nep55AssetStore.Get(key).AsBigInteger();
                if (mount > nep55Locked)
                    throw new InvalidOperationException("The tranafer mount can not be larger than current.");

                byte[] keyDest = concatKey(concatKey(destAddr, ASSET_NEP55), assetName);
                BigInteger destLocked = nep55AssetStore.Get(keyDest).AsBigInteger();

                nep55AssetStore.Put(key, nep55Locked - mount);
                nep55AssetStore.Put(keyDest, destLocked + mount);
                Transfered(srcAddr, destAddr, srcName.AsByteArray(), destName.AsByteArray(),assetType.AsByteArray(), assetName.AsByteArray(), mount);
            }
            authTotal.Put(keyTotal, total-mount);
            return true;
        }

        /// <summary>
        /// get user balance from contract.
        /// </summary>
        /// <param name="addr">user address</param>
        /// <param name="srcName">account name,it's unique</param> 
        /// <param name="destName">account name,it's unique</param>
        /// <param name="assetType">nep5 or nep55</param>
        /// <param name="assetName">nep5:sds_account/nep55:SD-HELLO</param>
        /// <param name="mount">transfer mount</param>
        /// <returns>boolean</returns>
        [DisplayName("getBalance")]
        public static BigInteger GetBalance(string username,string type, string assetName)
        {
            StorageMap accountInfo = Storage.CurrentContext.CreateMap(nameof(accountInfo));
            var result = accountInfo.Get(username);
            if (result.Length == 0)
                throw new InvalidOperationException("The accountInfo can not be null.");

            AccountInfo info = Helper.Deserialize(result) as AccountInfo;
            byte[] addr = info.owner;
          
            BigInteger balance = 0;
            if (type == ASSET_NEP5)
            {
                //check nep5 asset
                StorageMap nep5AssetStore = Storage.CurrentContext.CreateMap(nameof(nep5AssetStore));
                byte[] key = concatKey(concatKey(addr, ASSET_NEP5), assetName);
                balance = nep5AssetStore.Get(key).AsBigInteger(); 
            }
            else if (type == ASSET_NEP55)
            {
                //check nep55 asset
                StorageMap nep55AssetStore = Storage.CurrentContext.CreateMap(nameof(nep55AssetStore));
                byte[] key = concatKey(concatKey(addr, ASSET_NEP55), assetName);
                balance = nep55AssetStore.Get(key).AsBigInteger();
            }
            return balance;
        }

        [DisplayName("setAccount")]
        public static bool SetAccount(string key, byte[] address)
        {
            if (key.Length <= 0)
                throw new InvalidOperationException("The parameter key SHOULD be longer than 0.");

            if (address.Length != 20)
                throw new InvalidOperationException("The parameters address and to SHOULD be 20-byte addresses.");

            if (!checkAdmin()) return false;

            StorageMap asset = Storage.CurrentContext.CreateMap(nameof(asset));
            asset.Put(key,address);
            return true;
        }


        private static bool checkAdmin()
        {
            StorageMap account = Storage.CurrentContext.CreateMap(nameof(account));
            byte[] currAdmin = account.Get(ADMIN_ACCOUNT);

            if (currAdmin.Length > 0)
            {

                if (!Runtime.CheckWitness(currAdmin)) return false;
            }
            else
            {
                if (!Runtime.CheckWitness(committee)) return false;
            }
            return true;
        }


        [DisplayName("getAccount")]
        public static byte[] GetAccount(string key)
        {
            StorageMap asset = Storage.CurrentContext.CreateMap(nameof(asset));
            return asset.Get(key);
        }

        private static byte[] concatKey(byte[] addr,string type) {
            return addr.Concat(type.AsByteArray());
        }

        /**
         * check name of stablecoin
         */
        private static bool checkName(byte[] addr,string name)
        {
            foreach (var c in name)
            {
                if ('A' <= c && c <= 'Z')
                {
                    continue;
                }
                else if ('a' <= c && c <= 'z')
                {
                    continue;
                }
                else
                {
                    return false;
                }
            }
            //check name is useful.
            StorageMap nameInfo = Storage.CurrentContext.CreateMap(nameof(nameInfo));
            string ret = nameInfo.Get(addr).AsString();
            if (ret.Length > 0) return false;
            return true;
        }

        public class AccountInfo
        {

            //creator
            public byte[] owner;

            //key of this account
            public byte[] txid;

            //userName
            public string userName;

            //openTime 
            public uint openTime;

            //openHeight 
            public uint openHeight;

        }
    }
}