package org.consenlabs.tokencore.wallet;

import android.content.Context;
import android.text.TextUtils;
import android.util.Log;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;
import com.google.common.io.CharSource;
import com.google.common.io.Files;

import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.consenlabs.tokencore.foundation.utils.MnemonicUtil;
import org.consenlabs.tokencore.foundation.utils.NumericUtil;
import org.consenlabs.tokencore.wallet.address.AddressCreatorManager;
import org.consenlabs.tokencore.wallet.address.EthereumAddressCreator;
import org.consenlabs.tokencore.wallet.keystore.EOSKeystore;
import org.consenlabs.tokencore.wallet.keystore.HDMnemonicKeystore;
import org.consenlabs.tokencore.wallet.keystore.IMTKeystore;
import org.consenlabs.tokencore.wallet.keystore.Keystore;
import org.consenlabs.tokencore.wallet.keystore.LegacyEOSKeystore;
import org.consenlabs.tokencore.wallet.keystore.V3Keystore;
import org.consenlabs.tokencore.wallet.keystore.V3MnemonicKeystore;
import org.consenlabs.tokencore.wallet.keystore.WalletKeystore;
import org.consenlabs.tokencore.wallet.model.BIP44Util;
import org.consenlabs.tokencore.wallet.model.ChainType;
import org.consenlabs.tokencore.wallet.model.KeyPair;
import org.consenlabs.tokencore.wallet.model.Messages;
import org.consenlabs.tokencore.wallet.model.Metadata;
import org.consenlabs.tokencore.wallet.model.MnemonicAndPath;
import org.consenlabs.tokencore.wallet.model.Network;
import org.consenlabs.tokencore.wallet.model.TokenException;
import org.consenlabs.tokencore.wallet.validators.PrivateKeyValidator;
import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.annotation.Nullable;


public class WalletManager2 {
    /**
     * 钱包列表集合对象
     */
    private List<Wallet> walletList = Collections.synchronizedList(new ArrayList<>());
//    private static Hashtable<String, IMTKeystore> keystoreMap = new Hashtable<>();
    /**
     * 钱包保存地址
     */
    private static String walletPath;
    private static Context mContext;
    private static String loginUserId;
    private static final String LOG_TAG = WalletManager2.class.getSimpleName();

    private static WalletManager2 instance;

    public static WalletManager2 getInstance() {
        if (instance == null) {
            synchronized (WalletManager2.class) {
                if (instance == null) {
                    instance = new WalletManager2();
                }
            }
        }
        return instance;
    }

    /**
     * 可以认为初始化操作，当切换用户了，需要再次调用此方法
     *
     * @param context
     * @param userId
     */
    public void init(Context context, String userId) {
        mContext = context;
        loginUserId = userId;
        getWalletPath();
        // 初始化时，扫描当前所拥有的钱包列表
        scanWallets();
    }

    private String getWalletPath() {
        return walletPath = mContext.getFilesDir().getAbsolutePath() + File.separator + "wallet" + File.separator + loginUserId;
    }

    /**
     * 获取当前钱包列表对象
     *
     * @return
     */
    public List<Wallet> getWalletList() {
        return walletList;
    }

    public void clearWalletList() {
        walletList.clear();
    }


    /**
     * 根据IMTKeystore创建一个钱包对象
     *
     * @param keystore
     * @return
     */
    public Wallet createWallet(IMTKeystore keystore) {
        File file = generateWalletFile(keystore.getId());
        writeToFile(keystore, file);
        Wallet wallet = new Wallet(keystore);
        walletList.add(wallet);
        return wallet;
    }

    public Wallet changePassword(String id, String oldPassword, String newPassword) {
        IMTKeystore keystore = mustFindKeystoreById(id);
        IMTKeystore newKeystore = (IMTKeystore) keystore.changePassword(oldPassword, newPassword);
        return flushWallet(newKeystore, true);
    }

    /**
     * 修改钱包名字
     *
     * @param id
     * @param newName
     */
    public Wallet modifyName(String id, String newName) {
        IMTKeystore keystore = mustFindKeystoreById(id);
        keystore.getMetadata().setName(newName);
        return flushWallet(keystore, true);
    }

    /**
     * 验证密码是否正确
     *
     * @param id
     * @param password
     * @return
     */
    public boolean verifyPassword(String id, String password) {
        IMTKeystore keystore = mustFindKeystoreById(id);
        return keystore.verifyPassword(password);
    }

    public String exportPrivateKey(String id, String password) {
        Wallet wallet = mustFindWalletById(id);

        // TODO 这个判断包括判断里面的内容都是自己加的，原来没有
        if (wallet.getKeystore() instanceof HDMnemonicKeystore) {
            return exportHDMnemonicKeystorePrivateKey(wallet, password);
        }
        return wallet.exportPrivateKey(password);
    }


    /**
     * 导出HDMnemonicKeystore类型的私钥
     *
     * @param wallet
     * @return
     */
    private String exportHDMnemonicKeystorePrivateKey(Wallet wallet, String password) {
        String[] mnemonics = wallet.exportMnemonic(password).getMnemonic().split(" ");
        List<String> mnemonicsList = new ArrayList<>(Arrays.asList(mnemonics));
        return ((HDMnemonicKeystore) wallet.getKeystore()).getMainPrivateKey(mnemonicsList);
    }

//    /**
//     * 导出BTC钱包私钥
//     *
//     * @param id
//     * @param password
//     * @return
//     */
//    public static String exportBtcPrivateKey(String id, String password) {
//        Wallet wallet = mustFindWalletById(id);
//        String[] mnemonics = wallet.exportMnemonic(password).getMnemonic().split(" ");
//        List<String> mnemonicsList = new ArrayList<>(Arrays.asList(mnemonics));
//        return ((HDMnemonicKeystore) wallet.getKeystore()).getMainPrivateKey(mnemonicsList);
//    }

    public List<KeyPair> exportPrivateKeys(String id, String password) {
        Wallet wallet = mustFindWalletById(id);
        return wallet.exportPrivateKeys(password);
    }

    public MnemonicAndPath exportMnemonic(String id, String password) {
        Wallet wallet = mustFindWalletById(id);
        return wallet.exportMnemonic(password);
    }

    public String exportKeystore(String id, String password) {
        Wallet wallet = mustFindWalletById(id);
        return wallet.exportKeystore(password);
    }

    public void removeWallet(String id, String password) {
        Wallet wallet = mustFindWalletById(id);
        if (!wallet.verifyPassword(password)) {
            throw new TokenException(Messages.WALLET_INVALID_PASSWORD);
        }
        if (wallet.delete(password)) {
            walletList.remove(wallet);
        }
    }


    public Wallet importWalletFromKeystore(Metadata metadata, String keystoreContent, String password, boolean overwrite) {
        WalletKeystore importedKeystore = validateKeystore(keystoreContent, password);

        if (metadata.getSource() == null)
            metadata.setSource(Metadata.FROM_KEYSTORE);

        String privateKey = NumericUtil.bytesToHex(importedKeystore.decryptCiphertext(password));
        try {
            new PrivateKeyValidator(privateKey).validate();
        } catch (TokenException ex) {
            if (Messages.PRIVATE_KEY_INVALID.equals(ex.getMessage())) {
                throw new TokenException(Messages.KEYSTORE_CONTAINS_INVALID_PRIVATE_KEY);
            } else {
                throw ex;
            }
        }
        return importWalletFromPrivateKey(metadata, privateKey, password, overwrite);
    }

    public Wallet importWalletFromPrivateKey(Metadata metadata, String prvKeyHex, String password, boolean overwrite) {
        IMTKeystore keystore = V3Keystore.create(metadata, password, prvKeyHex);
        return flushWallet(keystore, overwrite);
    }

//    public static Wallet importWalletFromPrivateKeyByBTC(){
//        HDMnemonicKeystore keystore = HDMnemonicKeystore.create(Metadata);
//    }static Wallet importWalletFromPrivateKeyByBTC(){
//        HDMnemonicKeystore keystore = HDMnemonicKeystore.create(Metadata);
//    }

    /**
     * Just for import EOS wallet
     */
    public Wallet importWalletFromPrivateKeys(Metadata metadata, String accountName, List<String> prvKeys, List<EOSKeystore.PermissionObject> permissions, String password, boolean overwrite) {
        IMTKeystore keystore = null;
        if (!ChainType.EOS.equalsIgnoreCase(metadata.getChainType())) {
            throw new TokenException("This method is only for importing EOS wallet");
        }
        keystore = EOSKeystore.create(metadata, password, accountName, prvKeys, permissions);
        return persistWallet(keystore, overwrite);
    }

    /**
     * use the importWalletFromPrivateKeys
     */
    @Deprecated
    public Wallet importWalletFromPrivateKey(Metadata metadata, String accountName, String prvKeyHex, String password, boolean overwrite) {
        IMTKeystore keystore = LegacyEOSKeystore.create(metadata, accountName, password, prvKeyHex);
        return persistWallet(keystore, overwrite);
    }


    /**
     * import wallet from mnemonic
     *
     * @param metadata
     * @param accountName only for EOS
     * @param mnemonic
     * @param path
     * @param permissions only for EOS
     * @param password
     * @param overwrite
     * @return
     */
    public Wallet importWalletFromMnemonic(Metadata metadata, @Nullable String accountName, String mnemonic, String path, @Nullable List<EOSKeystore.PermissionObject> permissions, String password, boolean overwrite) {

        if (metadata.getSource() == null)
            metadata.setSource(Metadata.FROM_MNEMONIC);
        IMTKeystore keystore = null;
        List<String> mnemonicCodes = Arrays.asList(mnemonic.split(" "));
        MnemonicUtil.validateMnemonics(mnemonicCodes);
        switch (metadata.getChainType()) {
            case ChainType.ETHEREUM:
                keystore = V3MnemonicKeystore.create(metadata, password, mnemonicCodes, path);
                break;
            case ChainType.BITCOIN:
                keystore = HDMnemonicKeystore.create(metadata, password, mnemonicCodes, path);
                break;
            case ChainType.EOS:
                keystore = EOSKeystore.create(metadata, password, accountName, mnemonicCodes, path, permissions);
        }
        return persistWallet(keystore, overwrite);
    }

    public Wallet importWalletFromMnemonic(Metadata metadata, String mnemonic, String path, String password, boolean overwrite) {
        return importWalletFromMnemonic(metadata, null, mnemonic, path, null, password, overwrite);
    }

    public Wallet findWalletByPrivateKey(String chainType, String network, String privateKey, String segWit) {
        if (ChainType.ETHEREUM.equals(chainType)) {
            new PrivateKeyValidator(privateKey).validate();
        }
        Network net = new Network(network);
        String address = AddressCreatorManager.getInstance(chainType, net.isMainnet(), segWit).fromPrivateKey(privateKey);
        return findWalletByAddress(chainType, address);
    }

    public Wallet findWalletByKeystore(String chainType, String keystoreContent, String password) {
        WalletKeystore walletKeystore = validateKeystore(keystoreContent, password);

        byte[] prvKeyBytes = walletKeystore.decryptCiphertext(password);
        String address = new EthereumAddressCreator().fromPrivateKey(prvKeyBytes);
        return findWalletByAddress(chainType, address);
    }

    public Wallet findWalletByMnemonic(String chainType, String network, String mnemonic, String path, String segWit) {
        List<String> mnemonicCodes = Arrays.asList(mnemonic.split(" "));
        MnemonicUtil.validateMnemonics(mnemonicCodes);
        DeterministicSeed seed = new DeterministicSeed(mnemonicCodes, null, "", 0L);
        DeterministicKeyChain keyChain = DeterministicKeyChain.builder().seed(seed).build();
        if (Strings.isNullOrEmpty(path)) {
            throw new TokenException(Messages.INVALID_MNEMONIC_PATH);
        }

        if (ChainType.BITCOIN.equalsIgnoreCase(chainType)) {
            path += "/0/0";
        }

        DeterministicKey key = keyChain.getKeyByPath(BIP44Util.generatePath(path), true);
        Network net = new Network(network);
        String address = AddressCreatorManager.getInstance(chainType, net.isMainnet(), segWit).fromPrivateKey(key.getPrivateKeyAsHex());
        return findWalletByAddress(chainType, address);
    }

    public Wallet switchBTCWalletMode(String id, String password, String model) {
        Wallet wallet = mustFindWalletById(id);
        // !!! Warning !!! You must verify password before you write content to keystore
        if (!wallet.getMetadata().getChainType().equalsIgnoreCase(ChainType.BITCOIN))
            throw new TokenException("Ethereum wallet can't switch mode");
        Metadata metadata = wallet.getMetadata().clone();
        if (metadata.getSegWit().equalsIgnoreCase(model)) {
            return wallet;
        }

        metadata.setSegWit(model);
        IMTKeystore keystore;
        if (wallet.hasMnemonic()) {

            MnemonicAndPath mnemonicAndPath = wallet.exportMnemonic(password);
            String path = BIP44Util.getBTCMnemonicPath(model, metadata.isMainNet());
            List<String> mnemonicCodes = Arrays.asList(mnemonicAndPath.getMnemonic().split(" "));
            keystore = new HDMnemonicKeystore(metadata, password, mnemonicCodes, path, wallet.getId());
        } else {
            String prvKey = wallet.exportPrivateKey(password);
            keystore = new V3Keystore(metadata, password, prvKey, wallet.getId());

        }
        flushWallet(keystore, false);
        Wallet newWallet = new Wallet(keystore);
        walletList.add(newWallet);
        return newWallet;
    }

    public Wallet setAccountName(String id, String accountName) {
        Wallet wallet = mustFindWalletById(id);
        wallet.setAccountName(accountName);
        return persistWallet(wallet.getKeystore(), true);
    }

    public Wallet findWalletById(String id) {
        for (Wallet wallet : walletList) {
            if (TextUtils.equals(wallet.getKeystore().getId(), id)) {
                return wallet;
            }
        }
        return null;
    }

    public Wallet mustFindWalletById(String id) {
        for (Wallet wallet : walletList) {
            if (TextUtils.equals(wallet.getId(), id)) {
                return wallet;
            }
        }
        throw new TokenException(Messages.WALLET_NOT_FOUND);
    }


    public File generateWalletFile(String walletID) {
        return new File(getDefaultKeyDirectory(), walletID + ".json");
    }


//    static File getDefaultKeyDirectory() {
////        File directory = new File(storage.getKeystoreDir(), "wallets");
//        File directory = new File(getWalletPath(), "wallets");
//        if (!directory.exists()) {
//            directory.mkdirs();
//        }/data/user/0/com.zxtd.paychat/files/wallet/505471324932538368
//        return directory;
//    }

    public File getDefaultKeyDirectory() {
        if (TextUtils.isEmpty(walletPath)) {
            getWalletPath();
        }
        File directory = new File(walletPath);
        if (!directory.exists()) {
            directory.mkdirs();
        }
        return directory;
    }

    public boolean cleanKeystoreDirectory() {
        return deleteDir(getDefaultKeyDirectory());
    }

    private Wallet persistWallet(IMTKeystore keystore, boolean overwrite) {
        return flushWallet(keystore, overwrite);
    }


    public Wallet findWalletByAddress(String type, String address) {
        int size = walletList.size();
        for (int i = 0; i < size; i++) {
            Wallet wallet = walletList.get(i);
            if (TextUtils.equals(wallet.getAddress(), address) && TextUtils.equals(type, wallet.getMetadata().getChainType())) {
                wallet.setTag(i);
                return wallet;
            }
        }
        return null;
    }


    private Wallet flushWallet(IMTKeystore keystore, boolean overwrite) {
        Wallet wallet = findWalletByAddress(keystore.getMetadata().getChainType(), keystore.getAddress());
        if (wallet != null) {
            if (!overwrite) {
                throw new TokenException(Messages.WALLET_EXISTS);
            } else {
                keystore.setId(wallet.getKeystore().getId());
            }
        }
        File file = generateWalletFile(keystore.getId());
        writeToFile(keystore, file);
        Wallet newWallet = new Wallet(keystore);
        if (wallet != null) {
            int position = wallet.getTag();
            walletList.remove(position);
            walletList.add(position, newWallet);
        } else {
            walletList.add(newWallet);
        }
        return newWallet;
    }

    private static void writeToFile(Keystore keyStore, File destination) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper.writeValue(destination, keyStore);
        } catch (IOException ex) {
            throw new TokenException(Messages.WALLET_STORE_FAIL, ex);
        }
    }

    private static boolean deleteDir(File dir) {
        if (dir.isDirectory()) {
            String[] children = dir.list();
            for (String child : children) {
                boolean success = deleteDir(new File(dir, child));
                if (!success) {
                    return false;
                }
            }
        }
        return dir.delete();
    }

    private V3Keystore validateKeystore(String keystoreContent, String password) {
        V3Keystore importedKeystore = unmarshalKeystore(keystoreContent, V3Keystore.class);
        if (Strings.isNullOrEmpty(importedKeystore.getAddress()) || importedKeystore.getCrypto() == null) {
            throw new TokenException(Messages.WALLET_INVALID_KEYSTORE);
        }

        importedKeystore.getCrypto().validate();

        if (!importedKeystore.verifyPassword(password))
            throw new TokenException(Messages.MAC_UNMATCH);

        byte[] prvKey = importedKeystore.decryptCiphertext(password);
        String address = new EthereumAddressCreator().fromPrivateKey(prvKey);
        if (Strings.isNullOrEmpty(address) || !address.equalsIgnoreCase(importedKeystore.getAddress())) {
            throw new TokenException(Messages.PRIVATE_KEY_ADDRESS_NOT_MATCH);
        }
        return importedKeystore;
    }

    private IMTKeystore mustFindKeystoreById(String id) {
        for (Wallet wallet : walletList) {
            if (TextUtils.equals(wallet.getKeystore().getId(), id)) {
                return wallet.getKeystore();
            }
        }
        throw new TokenException(Messages.WALLET_NOT_FOUND);
    }

    private <T extends WalletKeystore> T unmarshalKeystore(String keystoreContent, Class<T> clazz) {
        T importedKeystore;
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            mapper.configure(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, true);
            importedKeystore = mapper.readValue(keystoreContent, clazz);
        } catch (IOException ex) {
            throw new TokenException(Messages.WALLET_INVALID_KEYSTORE, ex);
        }
        return importedKeystore;
    }

    public void scanWallets() {
        File directory = getDefaultKeyDirectory();

        walletList.clear();
        for (File file : directory.listFiles()) {
            if (!file.getName().startsWith("identity")) {
                try {
                    IMTKeystore keystore = null;
                    CharSource charSource = Files.asCharSource(file, Charset.forName("UTF-8"));
                    String jsonContent = charSource.read();
                    JSONObject jsonObject = new JSONObject(jsonContent);
                    int version = jsonObject.getInt("version");
                    if (version == 3) {
                        if (jsonContent.contains("encMnemonic")) {
                            keystore = unmarshalKeystore(jsonContent, V3MnemonicKeystore.class);
                        } else if (jsonObject.has("imTokenMeta") && ChainType.EOS.equals(jsonObject.getJSONObject("imTokenMeta").getString("chainType"))) {
                            keystore = unmarshalKeystore(jsonContent, LegacyEOSKeystore.class);
                        } else {
                            keystore = unmarshalKeystore(jsonContent, V3Keystore.class);
                        }
                    } else if (version == 1) {
                        keystore = unmarshalKeystore(jsonContent, V3Keystore.class);
                    } else if (version == 44) {
                        keystore = unmarshalKeystore(jsonContent, HDMnemonicKeystore.class);
                    } else if (version == 10001) {
                        keystore = unmarshalKeystore(jsonContent, EOSKeystore.class);
                    }

                    if (keystore != null) {
                        walletList.add(new Wallet(keystore));
                    }

                } catch (Exception ex) {
                    Log.e(LOG_TAG, "Can't loaded " + file.getName() + " file", ex);
                    continue;
                }
            }
        }
        Log.i("llj", "本地钱包个数------>>>" + walletList.size());
    }

    private WalletManager2() {
    }


    public enum WalletType {
        BITCOIN, ETHEREUM, EOS
    }

    /**
     * 创建一个钱包
     *
     * @param type
     * @param name
     * @param password
     * @param passwordHit
     * @param network
     * @param segWit
     * @param isNew       是创建一个新的钱包还是恢复的钱包
     * @return
     */
    public Wallet createWallet(WalletType type, String name, String password, String passwordHit, String network, String segWit, boolean isNew) {
        List<String> mnemonics = MnemonicUtil.randomMnemonicCodes();
        Log.i("llj", "创建之前的助记词---mnemonics.toString()----->>>" + mnemonics.toString());
        Metadata metadata = new Metadata();
        metadata.setName(name);
        metadata.setPasswordHint(passwordHit);
        // 是创建一个新的钱包还是恢复的钱包
        metadata.setSource(isNew ? Metadata.FROM_NEW_IDENTITY : Metadata.FROM_RECOVERED_IDENTITY);
        metadata.setNetwork(network);
        metadata.setSegWit(segWit);
        metadata.setTimestamp(System.currentTimeMillis() / 1000);
        Wallet wallet;
        switch (type) {
            case BITCOIN:
                wallet = deriveBitcoinWallet(mnemonics, password, metadata);
                break;
            case ETHEREUM:
                wallet = deriveEthereumWallet(mnemonics, password, metadata);
                break;
            case EOS:
                wallet = deriveEOSWallet(mnemonics, password, metadata);
                break;
            default:
                throw new TokenException(String.format("Doesn't support deriving %s wallet", ""));
        }
        return wallet;
    }

    /**
     * 导入钱包（助记词）
     *
     * @param type
     * @param mnemonic
     * @param name
     * @param password
     * @return
     */
    public Wallet importWalletFromMnemonic(WalletType type, String mnemonic, String name, String password, String network, String setWit) {
        Metadata metadata = new Metadata();
        metadata.setName(name);
        metadata.setPasswordHint("");
        // 从助记词导入
        metadata.setSource(Metadata.FROM_MNEMONIC);
        metadata.setNetwork(network);
        metadata.setSegWit(setWit);
        metadata.setTimestamp(System.currentTimeMillis() / 1000);

        String path;
        switch (type) {
            case BITCOIN:
                if (Metadata.P2WPKH.equals(metadata.getSegWit())) {
                    path = metadata.isMainNet() ? BIP44Util.BITCOIN_SEGWIT_MAIN_PATH : BIP44Util.BITCOIN_SEGWIT_TESTNET_PATH;
                } else {
                    path = metadata.isMainNet() ? BIP44Util.BITCOIN_MAINNET_PATH : BIP44Util.BITCOIN_TESTNET_PATH;
                }
                metadata.setChainType(ChainType.BITCOIN);
                break;
            case ETHEREUM:
                path = BIP44Util.ETHEREUM_PATH;
                metadata.setChainType(ChainType.ETHEREUM);
                break;
            case EOS:
                path = BIP44Util.EOS_LEDGER;
                metadata.setChainType(ChainType.EOS);
                break;
            default:
                // 其它币种直接返回
                return null;
        }
        return importWalletFromMnemonic(metadata, mnemonic, path, password, true);
    }


    /**
     * 导入钱包(私钥)
     *
     * @param type
     * @param privateKey
     * @param name
     * @param password
     * @return
     */
    public Wallet importWalletFromPrivateKey(WalletType type, String privateKey, String name, String password, String network, String segWit) {
        Metadata metadata = new Metadata();
        metadata.setName(name);
        metadata.setPasswordHint("");
        metadata.setNetwork(network);
        metadata.setTimestamp(System.currentTimeMillis() / 1000);
        metadata.setSegWit(segWit);
        switch (type) {
            case BITCOIN:
                metadata.setChainType(ChainType.BITCOIN);
                // 从WIF
                metadata.setSource(Metadata.FROM_WIF);
                break;
            case ETHEREUM:
                metadata.setChainType(ChainType.ETHEREUM);
                // 从私钥导入
                metadata.setSource(Metadata.FROM_PRIVATE);
                break;
            case EOS:
                metadata.setChainType(ChainType.EOS);
                break;
        }
        return importWalletFromPrivateKey(metadata, privateKey, password, true);
    }

    /**
     * 创建btc钱包
     *
     * @param mnemonicCodes
     * @param password
     * @return
     */
    private Wallet deriveBitcoinWallet(List<String> mnemonicCodes, String password, Metadata metadata) {
        metadata.setChainType(ChainType.BITCOIN);
        String path;
        if (Metadata.P2WPKH.equals(metadata.getSegWit())) {
            path = metadata.isMainNet() ? BIP44Util.BITCOIN_SEGWIT_MAIN_PATH : BIP44Util.BITCOIN_SEGWIT_TESTNET_PATH;
        } else {
            path = metadata.isMainNet() ? BIP44Util.BITCOIN_MAINNET_PATH : BIP44Util.BITCOIN_TESTNET_PATH;
        }
        IMTKeystore keystore = HDMnemonicKeystore.create(metadata, password, mnemonicCodes, path);
        return createWallet(keystore);
    }

    /**
     * 创建eth钱包
     *
     * @param mnemonics
     * @param password
     * @return
     */
    private Wallet deriveEthereumWallet(List<String> mnemonics, String password, Metadata metadata) {
        metadata.setChainType(ChainType.ETHEREUM);
        IMTKeystore keystore = V3MnemonicKeystore.create(metadata, password, mnemonics, BIP44Util.ETHEREUM_PATH);
        return createWallet(keystore);
    }

    /**
     * 创建eos钱包
     *
     * @param mnemonics
     * @param password
     * @return
     */
    private Wallet deriveEOSWallet(List<String> mnemonics, String password, Metadata metadata) {
        metadata.setChainType(ChainType.EOS);
        IMTKeystore keystore = EOSKeystore.create(metadata, password, "", mnemonics, BIP44Util.EOS_LEDGER, null);
        return createWallet(keystore);
    }
}
