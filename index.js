const { ApiPromise, WsProvider }  = require("@polkadot/api");
const ethUtil = require('ethereumjs-util');
const abi = require('ethereumjs-abi');
const { u8aToHex, hexToU8a } =  require("@polkadot/util");
const { blake2AsU8a } =  require('@polkadot/util-crypto');
const { BN } =  require("@polkadot/util");
const { identity, isBn, isFunction, isNumber, isString, isU8a, objectSpread } =  require('@polkadot/util');
const { Buffer } =  require('buffer');
const { Web3 } =  require('web3');
const eth_sig_utils = require("@metamask/eth-sig-util");
const eth_util = require("ethereumjs-util");


const typedData = {
    types: {
        EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' },
        ],
        Person: [
            { name: 'name', type: 'string' },
            { name: 'wallet', type: 'address' }
        ],
        Mail: [
            { name: 'from', type: 'Person' },
            { name: 'to', type: 'Person' },
            { name: 'contents', type: 'string' }
        ],
    },
    primaryType: 'Mail',
    domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 1,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    message: {
        from: {
            name: 'Cow',
            wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
        },
        to: {
            name: 'Bob',
            wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
        },
        contents: 'Hello, Bob!',
    },
};

const types = typedData.types;

function makeSignOptions(api, partialOptions, extras) {
    return objectSpread({ blockHash: api.genesisHash, genesisHash: api.genesisHash }, partialOptions, extras, { runtimeVersion: api.runtimeVersion, signedExtensions: api.registry.signedExtensions, version: api.extrinsicType });
}

function makeEraOptions(api, registry, partialOptions, { header, mortalLength, nonce }) {
    if (!header) {
        if (partialOptions.era && !partialOptions.blockHash) {
            throw new Error('Expected blockHash to be passed alongside non-immortal era options');
        }
        if (isNumber(partialOptions.era)) {
            // since we have no header, it is immortal, remove any option overrides
            // so we only supply the genesisHash and no era to the construction
            delete partialOptions.era;
            delete partialOptions.blockHash;
        }
        return makeSignOptions(api, partialOptions, { nonce });
    }
    return makeSignOptions(api, partialOptions, {
        blockHash: header.hash,
        era: registry.createTypeUnsafe('ExtrinsicEra', [{
            current: header.number,
            period: partialOptions.era || mortalLength
        }]),
        nonce
    });
}

// Recursively finds all the dependencies of a type
function dependencies(primaryType, found = []) {
    if (found.includes(primaryType)) {
        return found;
    }
    if (types[primaryType] === undefined) {
        return found;
    }
    found.push(primaryType);
    for (let field of types[primaryType]) {
        for (let dep of dependencies(field.type, found)) {
            if (!found.includes(dep)) {
                found.push(dep);
            }
        }
    }
    return found;
}

function encodeType(primaryType) {
    // Get dependencies primary first, then alphabetical
    let deps = dependencies(primaryType);
    deps = deps.filter(t => t != primaryType);
    deps = [primaryType].concat(deps.sort());

    // Format as a string with fields
    let result = '';
    for (let type of deps) {
        result += `${type}(${types[type].map(({ name, type }) => `${type} ${name}`).join(',')})`;
    }
    return result;
}

function typeHash(primaryType) {
    return ethUtil.keccakFromString(encodeType(primaryType), 256);
}

function encodeData(primaryType, data) {
    let encTypes = [];
    let encValues = [];

    // Add typehash
    encTypes.push('bytes32');
    encValues.push(typeHash(primaryType));

    // Add field contents
    for (let field of types[primaryType]) {
        let value = data[field.name];
        if (field.type == 'string' || field.type == 'bytes') {
            encTypes.push('bytes32');
            value = ethUtil.keccakFromString(value, 256);
            encValues.push(value);
        } else if (types[field.type] !== undefined) {
            encTypes.push('bytes32');
            value = ethUtil.keccak256(encodeData(field.type, value));
            encValues.push(value);
        } else if (field.type.lastIndexOf(']') === field.type.length - 1) {
            throw 'TODO: Arrays currently unimplemented in encodeData';
        } else {
            encTypes.push(field.type);
            encValues.push(value);
        }
    }

    return abi.rawEncode(encTypes, encValues);
}

function structHash(primaryType, data) {
    return ethUtil.keccak256(encodeData(primaryType, data));
}

function signHash() {
    return ethUtil.keccak256(
        Buffer.concat([
            Buffer.from('1901', 'hex'),
            structHash('EIP712Domain', typedData.domain),
            structHash(typedData.primaryType, typedData.message),
        ]),
    );
}

async function main() {


    const api = await ApiPromise.create({
        provider: new WsProvider("ws://127.0.0.1:9946"),
        rpc: {
            metamask: {
                get_eip712_sign_data: {
                    description: "",
                    params: [
                        {
                            name: "call",
                            type: "String"
                        },
                    ],
                    type: "String"
                }
            }
        },
        types: {
            MultiSignature: {
                _enum: {
                    Ed25519: 'Ed25519Signature',
                    Sr25519: 'Sr25519Signature',
                    Ecdsa: 'EcdsaSignature',
                    Eth: 'EcdsaSignature',
                }
            },
            ShufflingSeed: {
                seed: "H256",
                proof: "H512"
            },
            Header: {
                parentHash: "Hash",
                number: "Compact<BlockNumber>",
                stateRoot: "Hash",
                extrinsicsRoot: "Hash",
                digest: "Digest",
                seed: "ShufflingSeed",
                count: "BlockNumber"
            },
        }
    });

    let tx = api.tx.tokens.transfer("HWyLYmpW68JGJYoVJcot6JQ1CJbtUQeTdxfY1kUTsvGCB1r", 0, 1000);

    const extrinsic = api.createType(
        'Extrinsic',
        {method: tx.method},
        {version: tx.version}
    );

    let ethAddress = "0x9428406f4f4b467B7F5B8d6f4f066dD9d884D24B"
    let dotAddress = blake2AsU8a(hexToU8a(ethAddress));
    let options = {};
    let signingInfo = await api.derive.tx.signingInfo(dotAddress, options.nonce, options.era);
    const eraOptions = makeEraOptions(api, api.registry, options, signingInfo);
    let tx_payload = tx.inner.signature.createPayload(tx.method, eraOptions);
    let raw_payload = tx_payload.toU8a({ method: true });
    let result = await api.rpc.metamask.get_eip712_sign_data(tx.toHex().slice(2));
    console.log(JSON.stringify(result));
    let data = JSON.parse(result.toString());
    let data2 = {
        'types': {
            'EIP712Domain': [
                {'name': 'name', 'type': 'string'},
                {'name': 'version', 'type': 'string'},
                {'name': 'chainId', 'type': 'uint256'},
                {'name': 'verifyingContract', 'type': 'address'},
            ],
            'ChannelClose': [
                {'name': 'channel_adr', 'type': 'address'},
                {'name': 'channel_seq', 'type': 'uint32'},
                {'name': 'balance', 'type': 'uint256'},
            ],
        },
        'primaryType': 'ChannelClose',
        'domain': {
            'name': 'XBR',
            'version': '1',
            'chainId': 1,
            'verifyingContract': '0x254dffcd3277C0b1660F6d42EFbB754edaBAbC2B',
        },
        'message': [
            {"name":"method","type":"string"},
            {"name":"params","type":"string"},
            {"name":"tx","type":"string"}
        ],
    }
    data.message.tx = u8aToHex(raw_payload).slice(2);

    var msg_sig = eth_sig_utils.signTypedData(
        {
            privateKey: eth_util.toBuffer("0x2faacaa84871c08a596159fe88f8b2d05cf1ed861ac3d963c4a15593420cf53f"),
            data:  data,
            version: "V4" }
    );
    console.log("Ok, signed typed data ");
    console.log("SIGNATURE = " + msg_sig);
    let created_signature = api.createType('MultiSignature', {'Eth': hexToU8a(msg_sig)});
    console.log(tx_payload);
    console.log(msg_sig);
    extrinsic.addSignature(dotAddress, created_signature, tx_payload);
    await api.rpc.author.submitExtrinsic(extrinsic.toHex());
    console.log("Sent!!!")
}
main().then(  (x) => {
    console.log("Done") ;
    return;
    }
);