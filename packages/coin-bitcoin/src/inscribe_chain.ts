import * as bitcoin from "./bitcoinjs-lib";
import { base, signUtil } from "@okxweb3/crypto-lib";
import { countAdjustedVsize } from "./sigcost";
import { vectorSize } from "./bitcoinjs-lib/transaction";
import { privateKeyFromWIF, private2public, sign, wif2Public, getAddressType, private2Wif } from "./txBuild";
import * as taproot from "./taproot";
import * as bcrypto from "./bitcoinjs-lib/crypto";
import { isP2PKH, isP2SHScript, isP2TR } from "./bitcoinjs-lib/psbt/psbtutils";

/**
 * @description 铭文数据结构
 */
export type InscriptionData = {
    contentType: string // 内容类型，例如 "text/plain;charset=utf-8"
    body: string | Buffer // 铭文内容主体
    revealAddr: string // 接收铭文的地址
}

/**
 * @description 交易的先前输出信息 (UTXO)
 */
export type PrevOutput = {
    txId: string // UTXO 所在的交易 ID
    vOut: number // UTXO 在交易中的输出索引
    amount: number // UTXO 的金额 (单位: satoshi)
    address: string // UTXO 对应的地址
    privateKey: string // UTXO 地址对应的 WIF 格式私钥 (重要：用于签名)
    publicKey?: string // UTXO 地址对应的公钥 (可选，某些计算需要)
}

/**
 * @description 铭刻请求参数结构
 */
export type InscriptionRequest = {
    commitTxPrevOutputList: PrevOutput[] // 用于构建 Commit 交易的 UTXO 列表
    commitFeeRate: number // Commit 交易的费率 (单位: sat/vB)
    revealFeeRate: number // Reveal 交易的费率 (单位: sat/vB)
    inscriptionDataList: InscriptionData[] // 需要铭刻的数据列表
    revealOutValue: number // Reveal 交易的输出金额 (通常是 546 satoshi，即尘埃值)
    changeAddress: string // 接收找零的地址
    minChangeValue?: number // 最小找零金额，低于此值则不设找零 (可选，默认为 546 satoshi)
    // 以下字段可能在标准 inscribe 中使用，在此保留以兼容类型
    shareData?: string
    masterPublicKey?: string
    chainCode?: string
    commitTx?: string
    signatureList?: string[]
}

/**
 * @description 交易输出结构 (内部使用)
 */
export type TxOut = {
    pkScript: Buffer // 输出脚本 (锁定脚本)
    value: number // 输出金额 (单位: satoshi)
}

/**
 * @interface LastTxInfo
 * @description 存储每条交易链最后一个交易的详细信息，用于 RBF (Replace-By-Fee)
 */
export interface LastTxInfo {
  txId: string;               // 最后一个 Reveal 交易的 TxID
  hex: string;                // 最后一个 Reveal 交易的 Hex 字符串
  fee: number;                // 这个最后一个 Reveal 交易的预估费用 (satoshi)

  // --- RBF 重构所需输入信息 ---
  inputTxId: string;          // 它花费的交易 TxID (链中倒数第二个交易)
  inputVout: number;          // 它花费的交易的输出索引 Vout
  inputValue: number;         // 它花费的交易输出的金额 (satoshi)

  // --- RBF 重构所需输出信息 ---
  outputs: { pkScriptHex: string; value: number }[]; // 交易的输出数组 [{脚本Hex, 金额}, ...]

  // --- RBF 签名及重构所需上下文 ---
  signingPrivateKeyWIF: string; // 对 inputTxId:inputVout 进行签名所需的 WIF 格式私钥
  finalChangeAddress: string;   // 这条链最终的找零地址
  network: bitcoin.Network;     // 网络配置 (例如 bitcoin.networks.bitcoin)
  revealOutValue: number;       // 铭文固定输出金额 (satoshi)
  minChangeValue: number;       // 构建时使用的最小找零金额 (satoshi)
  prevInputPkScriptHex: string;  // 新增: 输入脚本 Hex
  revealPkScriptHex: string;     // 新增: 接收铭文脚本 Hex
  finalChangePkScriptHex: string; // 新增: 找零脚本 Hex
  tapScriptTreeHashHex: string;  // 新增: 脚本树哈希 Hex
  networkType: string;          // 新增: 网络类型
}

/**
 * @description 链式铭刻操作的返回结果类型
 */
export interface ChainInscribeResult {
    success: boolean;
    txChains: string[][];
    txChainTxIds: string[][];
    lastTxDetails: LastTxInfo[];
    totalEstimatedFee: number;
    error?: string; // 仅在 success 为 false 时存在
}

/**
 * @description 铭文交易构建所需的上下文数据 (内部使用)
 */
type InscriptionTxCtxData = {
    privateKey: Buffer // 原始私钥字节
    inscriptionScript: Buffer // 完整的铭文脚本 (包括 OP_FALSE OP_IF ... OP_ENDIF)
    commitTxAddress: string // P2TR Commit 地址
    commitTxAddressPkScript: Buffer // P2TR Commit 地址对应的输出脚本
    witness: Buffer[] // Reveal 交易花费 Commit 输出时所需的 Witness (不含签名)
    hash: Buffer // Script Tree 的 TapHash
    revealTxPrevOutput: TxOut // (此字段在链式铭刻中未使用，保留以兼容类型)
    revealPkScript: Buffer // 铭文接收地址对应的输出脚本
}

// --- 常量定义 ---
const DEFAULT_SEQUENCE_NUM = 0xfffffffd; // 默认 Sequence，允许 RBF
const MAX_TRANSACTIONS_PER_CHAIN = 25; // 单个链中最大交易数量限制 (比特币交易链长度限制约 25) - 修正为25
const DEFAULT_TX_VERSION = 2; // 默认交易版本号
const DEFAULT_REVEAL_OUT_VALUE = 546; // 默认 Reveal 输出金额 (尘埃值)
const DEFAULT_MIN_CHANGE_VALUE = 546; // 默认最小找零金额 (尘埃值)
const maxStandardTxWeight = 4000000 / 10; // 比特币标准交易最大权重 (约 400k vBytes)

// Schnorr 签名实例
const schnorr = signUtil.schnorr.secp256k1.schnorr;

/**
 * @class ChainInscriptionTool
 * @description 用于构建链式铭文交易 (Chain Inscription) 的工具类。
 *              将多个铭文通过一系列交易链接起来，允许使用一个或多个 UTXO 作为起始资金。
 *              此类包含了所有构建、费用估算、签名和信息记录的逻辑。
 */
export class ChainInscriptionTool {
    network: bitcoin.Network = bitcoin.networks.bitcoin; // 比特币网络配置
    inscriptionTxCtxDataList: InscriptionTxCtxData[] = []; // 所有铭文的上下文数据列表
    txChains: bitcoin.Transaction[][] = []; // 构建出的交易链，每个子数组是一条链
    utxoMap: Map<string, { amount: number, address: string, privateKey: string }> = new Map(); // 输入 UTXO 的映射，方便查找
    public totalEstimatedFee: number = 0; // 所有链的总预估费用
    // 记录每个交易 (chainIndex, txIndex) 对应的铭文上下文索引 (用于签名和 RBF 信息)
    public chainContextMapping: { chainIndex: number, txIndex: number, contextIndex: number | null }[] = [];
    // 记录每个交易 (chainIndex, txIndex) 的预估费用 (用于 RBF 信息)
    public txFees: { chainIndex: number, txIndex: number, fee: number }[] = [];

    /**
     * @constructor
     * @description ChainInscriptionTool 构造函数。
     */
    constructor() {
        // 构造函数内容可根据需要添加初始化逻辑
    }

    /**
     * @static
     * @function newChainInscriptionTool
     * @description 静态工厂方法，创建并初始化 ChainInscriptionTool 实例，并构建、签名交易链。
     * @param {bitcoin.Network} network - 比特币网络配置。
     * @param {InscriptionRequest} request - 链式铭刻请求参数。
     * @returns {ChainInscriptionTool} - 构建并签名完成的工具实例。
     * @throws {Error} 如果输入参数无效或构建/签名过程中发生错误。
     */
    static newChainInscriptionTool(network: bitcoin.Network, request: InscriptionRequest): ChainInscriptionTool {
        const tool = new ChainInscriptionTool();
        tool.network = network;
        // 获取或设置默认值
        const revealOutValue = request.revealOutValue || DEFAULT_REVEAL_OUT_VALUE;
        const minChangeValue = request.minChangeValue || DEFAULT_MIN_CHANGE_VALUE;

        // --- 参数验证 ---
        if (!request.commitTxPrevOutputList || request.commitTxPrevOutputList.length === 0) throw new Error("输入错误：commitTxPrevOutputList 不能为空");
        if (!request.inscriptionDataList || request.inscriptionDataList.length === 0) throw new Error("输入错误：inscriptionDataList 不能为空");

        // **重要:** 链式铭刻要求 commitTxPrevOutputList 中的每个 UTXO 都有私钥
        request.commitTxPrevOutputList.forEach((utxo, index) => {
            if (!utxo.privateKey) {
                throw new Error(`输入错误：commitTxPrevOutputList 中索引 ${index} 的 UTXO (txId: ${utxo.txId}) 缺少私钥 (privateKey)`);
            }
        });

        // --- 数据准备 ---
        // 1. 创建所有铭文的上下文数据
        //    重要：此处假设使用 commitTxPrevOutputList[0] 的私钥生成所有铭文的 commit 地址和签名 reveal 交易。
        //    如果需要每个 UTXO 或铭文有独立的控制私钥，需要修改 createInscriptionTxCtxData 的调用方式。
        const primaryPrivateKeyWif = request.commitTxPrevOutputList[0].privateKey;
        request.inscriptionDataList.forEach(inscriptionData => {
            tool.inscriptionTxCtxDataList.push(createInscriptionTxCtxData(network, inscriptionData, primaryPrivateKeyWif));
        });
        // 2. 初始化 UTXO 映射
        request.commitTxPrevOutputList.forEach(utxo => {
            const key = `${utxo.txId}:${utxo.vOut}`;
            tool.utxoMap.set(key, { amount: utxo.amount, address: utxo.address, privateKey: utxo.privateKey });
        });

        // --- 构建和签名 --- //
        // 3. 构建交易链 (内部会调用 buildSingleUtxoChain 并记录费用和映射)
        tool.buildEnhancedInscriptionChains(network, request.commitTxPrevOutputList, revealOutValue, request.revealFeeRate, request.changeAddress, minChangeValue, request.commitFeeRate);
        // 4. 签名所有构建出的交易
        tool.signAllTransactions(request.commitTxPrevOutputList);

        return tool;
    }

    /**
     * @function buildEnhancedInscriptionChains
     * @description 构建所有的铭文交易链，采用"顺序填充"策略。
     *              按顺序遍历铭文，为它们分配 UTXO。
     *              为每个 UTXO 构建尽可能满的交易链 (最多 maxInscriptionsPerChain 个铭文)。
     *              当一条链构建满或切换到新的 UTXO 时，开始构建下一条链。
     * @param {bitcoin.Network} network - 比特币网络配置。
     * @param {PrevOutput[]} commitTxPrevOutputList - 输入的 UTXO 列表。
     * @param {number} revealOutValue - Reveal 输出金额。
     * @param {number} revealFeeRate - Reveal 费率。
     * @param {string} changeAddress - 最终找零地址。
     * @param {number} minChangeValue - 最小找零金额。
     * @param {number} commitFeeRate - Commit 费率。
     * @returns {void}
     */
    buildEnhancedInscriptionChains( network: bitcoin.Network, commitTxPrevOutputList: PrevOutput[], revealOutValue: number, revealFeeRate: number, changeAddress: string, minChangeValue: number, commitFeeRate: number ): void {
        const totalInscriptions = this.inscriptionTxCtxDataList.length;
        const utxoCount = commitTxPrevOutputList.length;
        if (utxoCount === 0) {
             console.warn("链式铭刻警告：未提供任何 UTXO，无法构建交易链。")
             return;
        }
        if (totalInscriptions === 0) {
            console.warn("链式铭刻警告：没有需要铭刻的数据。")
            return;
        }

        // 定义每条链最多能容纳的铭文数量 (交易链长度 = Commit(1) + Reveals(N)) <= MAX_TRANSACTIONS_PER_CHAIN
        // 所以 N <= MAX_TRANSACTIONS_PER_CHAIN - 1
        const maxInscriptionsPerChain = MAX_TRANSACTIONS_PER_CHAIN - 1;

        let inscriptionStartIndex = 0; // 当前处理的铭文在总列表中的起始索引
        let currentUtxoIndex = 0; // 当前使用的 UTXO 在列表中的索引

        console.log(`链式铭刻信息：总铭文数=${totalInscriptions}, UTXO数=${utxoCount}, 每链最大铭文数=${maxInscriptionsPerChain}`);

        // --- 顺序填充循环 --- //
        while (inscriptionStartIndex < totalInscriptions) {
            // 检查 UTXO 是否用尽
            if (currentUtxoIndex >= utxoCount) {
                throw new Error(`链式铭刻错误：UTXO 数量 (${utxoCount}) 不足以处理所有铭文 (${totalInscriptions})。请确保调用前已筛选足够价值的 UTXO。`);
            }

            // 获取当前要使用的 UTXO
            const utxo = commitTxPrevOutputList[currentUtxoIndex];
            console.log(`使用 UTXO ${currentUtxoIndex} (${utxo.txId}:${utxo.vOut}, ${utxo.amount} sat) 开始构建新链...`);

            // 计算本次链最多能处理多少铭文
            const remainingInscriptions = totalInscriptions - inscriptionStartIndex;
            const countForThisChain = Math.min(remainingInscriptions, maxInscriptionsPerChain);

            // 获取本次链所需的铭文数据
            const segmentEndIndex = inscriptionStartIndex + countForThisChain;
            const inscriptionsForThisChain = this.inscriptionTxCtxDataList.slice(inscriptionStartIndex, segmentEndIndex);

            console.log(`  构建链片段：使用 UTXO ${currentUtxoIndex} 处理 ${countForThisChain} 个铭文 (全局索引 ${inscriptionStartIndex} 到 ${segmentEndIndex - 1})。`);

            // 健全性检查
            if (inscriptionsForThisChain.length === 0 || inscriptionsForThisChain.length !== countForThisChain) {
                console.error(`链式铭刻错误：尝试为 UTXO ${currentUtxoIndex} 构建链片段时，获取铭文数据失败 (预期 ${countForThisChain}, 实际 ${inscriptionsForThisChain.length})，索引范围 [${inscriptionStartIndex}, ${segmentEndIndex})`);
                // 遇到错误，最好是停止执行，避免后续问题
                throw new Error(`链式铭刻内部错误：无法获取铭文数据片段`);
            }

            // 构建单条（符合长度限制的）交易链
            const currentChainIndex = this.txChains.length; // 获取当前链的索引 (在添加之前)
            try {
                const txChain = this.buildSingleUtxoChain(
                    network,
                    utxo, // 使用当前 UTXO 作为起始资金
                    inscriptionsForThisChain, // 传入当前链段的铭文数据
                    revealOutValue,
                    revealFeeRate,
                    changeAddress,
                    minChangeValue,
                    commitFeeRate,
                    inscriptionStartIndex, // 传递正确的全局起始索引，用于映射
                    currentChainIndex // 传递当前链的索引
                );

                // 存储构建的链
                if (txChain.length > 0) {
                    this.txChains.push(txChain);
                    console.log(`  成功构建链 ${currentChainIndex}，包含 ${txChain.length} 笔交易。`);
                } else {
                    // 如果 buildSingleUtxoChain 返回空数组 (通常是资金不足或内部错误)
                    // 此时应该已经抛出错误了，这里只是额外的日志
                    console.warn(`链式铭刻警告：为 UTXO ${currentUtxoIndex} 的铭文片段 (索引 ${inscriptionStartIndex} 到 ${segmentEndIndex - 1}) 构建的交易链为空，可能发生错误。`);
                    // 考虑是否应该在此处也抛出错误或停止
                }
            } catch (e: any) {
                 console.error(`链式铭刻错误 (链 ${currentChainIndex}, 使用 UTXO ${currentUtxoIndex}): 构建交易链时发生错误: ${e.message}`);
                 throw e; // 将错误向上抛出
            }


            // 更新下一个铭文段的起始索引
            inscriptionStartIndex += countForThisChain;
            // 切换到下一个 UTXO 用于下一条链
            currentUtxoIndex++;

        } // end while (处理所有铭文)

        console.log(`链式铭刻构建完成：共构建了 ${this.txChains.length} 条交易链。`);

        // 最终检查：是否所有铭文都已被处理 (理论上循环结束后应始终匹配)
        if (inscriptionStartIndex !== totalInscriptions) {
            console.error(`链式铭刻严重错误：处理完所有铭文后，计数 (${inscriptionStartIndex}) 与总数 (${totalInscriptions}) 不匹配，可能存在逻辑错误！`);
        }
    }

    /**
     * @function buildSingleUtxoChain
     * @description 为单个 UTXO 构建一条完整的交易链 (包含一个初始 Commit 和多个 Reveal 交易)。
     * @param {bitcoin.Network} network - 比特币网络配置。
     * @param {PrevOutput} utxo - 此链使用的起始 UTXO。
     * @param {InscriptionTxCtxData[]} inscriptions - 分配给此链的铭文上下文数据列表。
     * @param {number} revealOutValue - Reveal 输出金额。
     * @param {number} revealFeeRate - Reveal 费率。
     * @param {string} finalChangeAddress - 整条链处理完毕后的最终找零地址。
     * @param {number} minChangeValue - 最小找零金额。
     * @param {number} commitFeeRate - 初始 Commit 交易的费率。
     * @param {number} inscriptionCtxStartIndex - 此批铭文在 `this.inscriptionTxCtxDataList` 中的起始索引 (用于记录映射)。
     * @param {number} chainIndex - 当前构建的是第几条链 (从 0 开始，用于记录映射和费用)。
     * @returns {bitcoin.Transaction[]} - 构建出的交易对象数组 (一条链)。
     * @throws {Error} 如果资金不足或发生内部错误。
     */
    buildSingleUtxoChain( network: bitcoin.Network, utxo: PrevOutput, inscriptions: InscriptionTxCtxData[], revealOutValue: number, revealFeeRate: number, finalChangeAddress: string, minChangeValue: number, commitFeeRate: number, inscriptionCtxStartIndex: number, chainIndex: number ): bitcoin.Transaction[] {
        const txChain: bitcoin.Transaction[] = [];
        const inscriptionCount = inscriptions.length;
        if (inscriptionCount === 0) return txChain; // 如果没有分配到铭文，则返回空链

        // --- 1. 构建初始 Commit 交易 (花费外部 UTXO) ---
        const initialCommitTx = new bitcoin.Transaction();
        initialCommitTx.version = DEFAULT_TX_VERSION;
        const utxoHash = base.reverseBuffer(base.fromHex(utxo.txId));
        initialCommitTx.addInput(utxoHash, utxo.vOut, DEFAULT_SEQUENCE_NUM); // 启用 RBF

        // Commit 交易的输出指向第一个铭文的 Commit 地址 (P2TR)
        const firstInscriptionCtx = inscriptions[0];
        initialCommitTx.addOutput(firstInscriptionCtx.commitTxAddressPkScript, 0); // 金额稍后计算

        // 估算费用并设置 Commit 交易的输出金额
        const { fee: initialCommitFee, changeAmount: commitOutputAmount } = this.estimateFeeAndOutput( initialCommitTx, [utxo], commitFeeRate, utxo.amount, 0, minChangeValue, true ); // 第三个参数 isCommitTx=true

        if (commitOutputAmount < 0) {
            // 资金不足以支付初始 Commit 费用，此链无法开始
            throw new Error(`链式铭刻错误 (链 ${chainIndex}): UTXO ${utxo.txId}:${utxo.vOut} (${utxo.amount} sat) 余额不足以支付初始 Commit 交易费用 (约 ${initialCommitFee} sat)`);
        }
        this.totalEstimatedFee += initialCommitFee; // 累加总费用
        this.txFees.push({ chainIndex, txIndex: 0, fee: initialCommitFee }); // 记录此交易费用
        this.chainContextMapping.push({ chainIndex, txIndex: 0, contextIndex: null }); // 记录映射 (Commit 交易无铭文上下文)
        initialCommitTx.outs[0].value = commitOutputAmount; // 设置 Commit 输出金额
        console.log(`链 ${chainIndex} - 初始 Commit TX (索引 0): 输入=${utxo.amount}, 输出=${commitOutputAmount}, 预估费用=${initialCommitFee}`);
        txChain.push(initialCommitTx);

        // --- 2. 构建后续的 Reveal 交易链 ---
        let prevTx = initialCommitTx; // 上一个交易
        let prevOutputValue = commitOutputAmount; // 上一个交易的相关输出金额 (用于本次输入)
        let prevOutputIndex = 0; // 上一个交易的相关输出索引 (Commit 交易只有一个输出，索引为 0)

        for (let i = 0; i < inscriptionCount; i++) {
            const inscriptionCtx = inscriptions[i]; // 当前处理的铭文上下文
            const isLastReveal = (i === inscriptionCount - 1); // 是否为链中最后一个 Reveal 交易
            const currentTxIndex = txChain.length; // 当前 Reveal 交易在此链中的索引 (从 1 开始)
            const contextIndexForThisReveal = inscriptionCtxStartIndex + i; // 当前铭文在总列表中的全局索引

            // 确定本次 Reveal 交易的找零地址
            // 如果是最后一个 Reveal，找零给 finalChangeAddress
            // 否则，找零给下一个铭文的 Commit 地址 (inscriptions[i+1].commitTxAddress)
            const currentChangeAddress = isLastReveal ? finalChangeAddress : inscriptions[i + 1]?.commitTxAddress;
            if (!currentChangeAddress) {
                // 理论上不应发生，因为 finalChangeAddress 必须提供，且非最后交易必有下一个铭文
                throw new Error(`链式铭刻内部错误 (链 ${chainIndex}, 铭文 ${i}): 无法确定 Reveal 交易的找零地址`);
            }

            // 创建 Reveal 交易
            const revealTx = new bitcoin.Transaction();
            revealTx.version = DEFAULT_TX_VERSION;
            // 添加输入：花费上一个交易的输出
            revealTx.addInput(prevTx.getHash(), prevOutputIndex, DEFAULT_SEQUENCE_NUM); // 启用 RBF

            // 添加输出 1: 铭文接收地址
            revealTx.addOutput(inscriptionCtx.revealPkScript, revealOutValue);
            // 添加输出 2: 找零地址 (金额稍后计算)
            const changePkScript = bitcoin.address.toOutputScript(currentChangeAddress, network);
            revealTx.addOutput(changePkScript, 0);

            // 估算费用并设置找零金额
            // 注意：输入信息需要包含上一个交易的输出金额 prevOutputValue
            const { fee: revealFee, changeAmount: revealChangeAmount } = this.estimateFeeAndOutput(
                revealTx,
                // 模拟 P2TR 输入，只需要金额和地址类型信息来估算 witness 大小
                [{ ...utxo, amount: prevOutputValue, address: firstInscriptionCtx.commitTxAddress, privateKey: '' }], // 使用第一个铭文的commit地址作为模拟地址类型
                revealFeeRate, // 使用 Reveal 费率
                prevOutputValue, // 本次交易的总输入金额
                revealOutValue, // 固定输出金额 (铭文)
                minChangeValue, // 最小找零要求
                false, // isCommitTx = false
                inscriptionCtx // 需要铭文上下文来估算 witness 大小
            );

            if (revealChangeAmount === -Infinity) {
                 // 即使无找零资金也不足
                 throw new Error(`链式铭刻错误 (链 ${chainIndex}, 铭文 ${i}): 交易链中断，余额 (${prevOutputValue} sat) 不足以支付 Reveal 费用 (约 ${revealFee} sat) + 铭文输出 (${revealOutValue} sat)`);
            } else if (revealChangeAmount === -1) {
                 // 找零不足，但无找零可行 (只允许发生在最后一个 Reveal 交易)
                 if (!isLastReveal) {
                     throw new Error(`链式铭刻错误 (链 ${chainIndex}, 铭文 ${i}): 交易链中断，非最后一个 Reveal 交易必须有找零，但余额 (${prevOutputValue} sat) 不足以支付 Reveal 费用 (约 ${revealFee} sat) + 铭文输出 (${revealOutValue} sat) + 最小找零 (${minChangeValue} sat)`);
                 }
                 console.log(`链 ${chainIndex} - Reveal TX (索引 ${currentTxIndex}): 最后一个铭文，无找零`);
                 revealTx.outs.pop(); // 移除找零输出
                 // 重新估算无找零时的费用 (理论上 fee 不变或略减小)
                 const { fee: revealFeeNoChange } = this.estimateFeeAndOutput( revealTx, [{ ...utxo, amount: prevOutputValue, address: firstInscriptionCtx.commitTxAddress, privateKey: '' }], revealFeeRate, prevOutputValue, revealOutValue, 0, false, inscriptionCtx );
                 this.totalEstimatedFee += revealFeeNoChange; // 累加总费用
                 this.txFees.push({ chainIndex, txIndex: currentTxIndex, fee: revealFeeNoChange }); // 记录费用
                 this.chainContextMapping.push({ chainIndex, txIndex: currentTxIndex, contextIndex: contextIndexForThisReveal }); // 记录映射
                 console.log(`链 ${chainIndex} - Reveal TX (索引 ${currentTxIndex}): 输入=${prevOutputValue}, 铭文输出=${revealOutValue}, 预估费用=${revealFeeNoChange}`);
                 prevOutputValue = 0; // 无找零，后续无可用余额
            } else if (revealChangeAmount >= minChangeValue) {
                 // 有足够的找零
                 this.totalEstimatedFee += revealFee; // 累加总费用
                 this.txFees.push({ chainIndex, txIndex: currentTxIndex, fee: revealFee }); // 记录费用
                 this.chainContextMapping.push({ chainIndex, txIndex: currentTxIndex, contextIndex: contextIndexForThisReveal }); // 记录映射
                 revealTx.outs[1].value = revealChangeAmount; // 设置找零金额
                 console.log(`链 ${chainIndex} - Reveal TX (索引 ${currentTxIndex}): 输入=${prevOutputValue}, 铭文输出=${revealOutValue}, 找零输出=${revealChangeAmount}, 预估费用=${revealFee}`);
                 prevOutputValue = revealChangeAmount; // 更新可用余额为找零金额
            } else {
                 // 理论上不应发生，因为上面覆盖了所有情况 (>= minChangeValue, -1, -Infinity)
                 throw new Error(`链式铭刻内部错误 (链 ${chainIndex}, 铭文 ${i}): 计算得到的找零金额异常: ${revealChangeAmount}`);
            }

            txChain.push(revealTx);

            // 更新 prevTx 和 prevOutputIndex 以供下一次迭代
            prevTx = revealTx;
            // 如果是最后一个 Reveal 且无找零，则 prevOutputIndex 无意义 (设为 -1 终止循环)
            // 否则，下一个输入应该花费本次交易的找零输出 (索引为 1)
            prevOutputIndex = isLastReveal && revealChangeAmount === -1 ? -1 : 1;
            if (prevOutputIndex === -1) break; // 链结束
        }

        return txChain;
    }

    /**
     * @function estimateFeeAndOutput
     * @description (内部辅助函数) 估算单个交易的费用和找零金额。
     * @param {bitcoin.Transaction} tx - 需要估算的交易对象 (已包含输入和输出结构，输出金额可能未设置)。
     * @param {PrevOutput[]} inputs - 交易的输入信息列表 (需要地址和私钥用于模拟签名)。
     * @param {number} feeRate - 费率 (sat/vB)。
     * @param {number} totalInputValue - 交易的总输入金额。
     * @param {number} fixedOutputValue - 交易中除找零外的固定输出金额总和 (Commit 交易通常为 0，Reveal 交易为 revealOutValue)。
     * @param {number} minChangeValue - 最小找零金额要求。
     * @param {boolean} isCommitTx - 是否为 Commit 交易。
     * @param {InscriptionTxCtxData | undefined} inscriptionCtx - 如果是 Reveal 交易，需要提供铭文上下文用于估算 Witness。
     * @returns {{ fee: number, changeAmount: number }} - 预估费用和找零金额。
     *          如果 changeAmount >= minChangeValue，表示有足够找零。
     *          如果 changeAmount === -1，表示找零不足但无找零可行。
     *          如果 changeAmount === -Infinity，表示即使无找零资金也依然不足。
     * @throws {Error} 如果估算所需信息不足。
     */
    estimateFeeAndOutput( tx: bitcoin.Transaction, inputs: PrevOutput[], feeRate: number, totalInputValue: number, fixedOutputValue: number, minChangeValue: number, isCommitTx: boolean, inscriptionCtx?: InscriptionTxCtxData ): { fee: number, changeAmount: number } {
        const txForEstimate = tx.clone(); // 克隆交易进行估算，不修改原交易

        // --- 模拟签名以获得准确的 VSize ---
        try {
            if (isCommitTx) {
                // 对 Commit 交易进行模拟签名
                signTx(txForEstimate, inputs, this.network);
            } else if (inscriptionCtx) {
                // 对 Reveal 交易模拟签名 (用占位符填充签名部分即可)
                const emptySignature = Buffer.alloc(64);
                if (txForEstimate.ins.length > 0 && txForEstimate.ins[0]) {
                    // P2TR 的 witness 结构是 [签名, 铭文脚本, 控制块]
                    txForEstimate.ins[0].witness = [emptySignature, ...inscriptionCtx.witness];
                } else {
                    throw new Error("费用估算内部错误：尝试估算一个没有输入的 Reveal 交易？");
                }
            } else {
                 throw new Error("费用估算内部错误：估算 Reveal 交易费用需要提供 inscriptionCtx");
            }
        } catch (e: any) {
            console.error(`费用估算错误：模拟签名失败: ${e.message}`);
            throw new Error(`费用估算错误：模拟签名失败: ${e.message}`);
        }


        // --- 计算 VSize 和费用 ---
        let vsize = 0;
        try {
            vsize = countAdjustedVsize(txForEstimate, inputs.map(i => i.address), this.network);
        } catch (e: any) {
            console.error(`费用估算错误：计算 VSize 失败: ${e.message}`);
            throw new Error(`费用估算错误：计算 VSize 失败: ${e.message}`);
        }
        // 费用至少为 1 sat/vB，向上取整
        const fee = Math.max(Math.ceil(vsize * feeRate), vsize);

        // --- 计算找零 --- //
        let changeAmount = totalInputValue - fixedOutputValue - fee;

        // 确定找零输出在 tx.outs 中的索引 (Commit 通常没有显式找零，Reveal 的是索引 1)
        const changeOutputIndex = isCommitTx ? -1 : 1;

        // 检查是否有找零输出槽位，并且计算出的找零金额是否低于最小要求
        if (changeOutputIndex !== -1 && tx.outs.length > changeOutputIndex) {
            if (!(changeAmount >= minChangeValue)) {
                // 找零金额不足，尝试移除找零输出并重新计算费用
                const txWithoutChange = tx.clone();
                // 移除找零输出 (索引 1)
                if (txWithoutChange.outs.length > changeOutputIndex) {
                    txWithoutChange.outs.splice(changeOutputIndex, 1);
                } else {
                     // 如果找不到 changeOutputIndex，说明逻辑有问题
                     throw new Error(`费用估算内部错误：期望在索引 ${changeOutputIndex} 找到找零输出，但输出数量为 ${txWithoutChange.outs.length}`);
                }
                const estimateTxWithoutChange = txWithoutChange.clone();
                // 重新模拟签名 (无找零版本)
                try {
                    if (isCommitTx) { // Commit 交易不应进入此逻辑
                        signTx(estimateTxWithoutChange, inputs, this.network);
                    } else if(inscriptionCtx) {
                        const emptySignature = Buffer.alloc(64);
                        if (estimateTxWithoutChange.ins.length > 0 && estimateTxWithoutChange.ins[0]) {
                            estimateTxWithoutChange.ins[0].witness = [emptySignature, ...inscriptionCtx.witness];
                        } else {
                            throw new Error("费用估算内部错误：尝试估算一个没有输入且无找零的 Reveal 交易？");
                        }
                    } else {
                         throw new Error("费用估算内部错误：估算 Reveal 交易费用需要提供 inscriptionCtx (无找零情况)");
                    }
                } catch (e: any) {
                    console.error(`费用估算错误：重新模拟签名 (无找零) 失败: ${e.message}`);
                    throw new Error(`费用估算错误：重新模拟签名 (无找零) 失败: ${e.message}`);
                }
                // 计算无找零时的 VSize 和费用
                let vsizeWithoutChange = 0;
                 try {
                    vsizeWithoutChange = countAdjustedVsize(estimateTxWithoutChange, inputs.map(i => i.address), this.network);
                } catch (e: any) {
                    console.error(`费用估算错误：重新计算 VSize (无找零) 失败: ${e.message}`);
                    throw new Error(`费用估算错误：重新计算 VSize (无找零) 失败: ${e.message}`);
                }
                const feeWithoutChange = Math.max(Math.ceil(vsizeWithoutChange * feeRate), vsizeWithoutChange);

                // 检查无找零时资金是否足够
                if (totalInputValue >= fixedOutputValue + feeWithoutChange) {
                    // 无找零可行
                    return { fee: feeWithoutChange, changeAmount: -1 }; // changeAmount = -1 表示无找零
                } else {
                    // 即使无找零，资金仍不足
                    return { fee: fee, changeAmount: -Infinity }; // changeAmount = -Infinity 表示资金不足
                }
            }
            // else: 找零金额足够，使用原始计算的 fee 和 changeAmount
        }
        // else: 没有找零输出槽位，或找零金额足够

        return { fee, changeAmount };
    }

    /**
     * @function signAllTransactions
     * @description 对构建出的所有交易链中的所有交易进行签名。
     * @param {PrevOutput[]} commitTxPrevOutputList - 原始输入的 UTXO 列表 (主要用于签名初始 Commit 交易)。
     * @returns {void}
     * @throws {Error} 如果签名过程中发生错误（例如找不到上下文、脚本不匹配等）。
     */
    signAllTransactions(commitTxPrevOutputList: PrevOutput[]): void {
        if (!this.txChains || this.txChains.length === 0) {
            console.warn('签名警告：没有构建任何交易链，无需签名。');
            return;
        }
        // 允许 UTXO 数量多于链数量 (未使用的 UTXO)
        if (this.txChains.length > commitTxPrevOutputList.length) {
             console.warn(`签名警告：交易链数量 (${this.txChains.length}) 大于提供的 UTXO 数量 (${commitTxPrevOutputList.length})，逻辑可能存在问题。`);
        }

        this.txChains.forEach((chain, chainIndex) => {
            // 安全检查：确保有对应的 UTXO 来签第一个 Commit 交易
            if (chainIndex >= commitTxPrevOutputList.length) {
                console.error(`签名错误：尝试为链 ${chainIndex} 签名，但 commitTxPrevOutputList 中没有对应的 UTXO (索引 ${chainIndex})`);
                return; // 跳过此链
            }
            const initialUtxo = commitTxPrevOutputList[chainIndex]; // 用于签第一个 Commit
            if (!initialUtxo || !initialUtxo.privateKey) {
                console.error(`签名错误：链 ${chainIndex} 对应的初始 UTXO (索引 ${chainIndex}) 无效或缺少私钥。`);
                return; // 跳过此链
            }
            let prevTxOutputs: bitcoin.Transaction['outs'] = []; // 存储上一个交易的输出列表

            chain.forEach((tx, txIndex) => {
                try {
                    if (txIndex === 0) {
                        // --- 签名初始 Commit 交易 ---
                        console.log(`签名：链 ${chainIndex} - 初始 Commit TX (索引 0)`);
                        signTx(tx, [initialUtxo], this.network); // 调用外部 signTx 函数签名
                        prevTxOutputs = tx.outs;
                    } else {
                        // --- 签名 Reveal 交易 ---
                        console.log(`签名：链 ${chainIndex} - Reveal TX (索引 ${txIndex})`);
                        const prevTx = chain[txIndex - 1]; // 获取上一个交易
                        const inputIndex = 0; // Reveal 交易只有一个输入
                        const outputSpentIndex = tx.ins[inputIndex].index; // 获取花费的是上一个交易的哪个输出

                        // 健全性检查：输出索引是否有效
                        if (outputSpentIndex >= prevTxOutputs.length) {
                            throw new Error(`签名错误 (链 ${chainIndex}, TX ${txIndex}): 尝试花费上一个交易 (TX ${txIndex-1}) 不存在的输出索引 ${outputSpentIndex}`);
                        }

                        const prevOutScript = prevTxOutputs[outputSpentIndex].script; // 被花费的输出脚本
                        const value = prevTxOutputs[outputSpentIndex].value; // 被花费的输出金额

                        // --- 查找对应的铭文上下文和私钥 --- //
                        // 使用之前记录的精确映射关系
                        const mapping = this.chainContextMapping.find(m => m.chainIndex === chainIndex && m.txIndex === txIndex);
                        if (!mapping || mapping.contextIndex === null || mapping.contextIndex === undefined) {
                            // 如果找不到映射或 contextIndex 为 null/undefined (Commit 交易？)，则无法签名
                            throw new Error(`签名错误 (链 ${chainIndex}, TX ${txIndex}): 未找到交易的铭文上下文映射信息`);
                        }
                        const inscriptionCtx = this.inscriptionTxCtxDataList[mapping.contextIndex];
                        if (!inscriptionCtx) {
                             throw new Error(`签名错误 (链 ${chainIndex}, TX ${txIndex}): 根据映射索引 ${mapping.contextIndex} 未找到铭文上下文数据`);
                        }

                        // 健全性检查：确保花费的脚本与铭文上下文的 Commit 脚本匹配
                        if (!inscriptionCtx.commitTxAddressPkScript.equals(prevOutScript)) {
                            console.error(`签名严重错误 (链 ${chainIndex}, TX ${txIndex}): 花费的脚本与找到的铭文上下文 (索引 ${mapping.contextIndex}) 的 Commit 脚本不匹配!`);
                            console.error(`  花费脚本: ${prevOutScript.toString('hex')}`);
                            console.error(`  上下文脚本: ${inscriptionCtx.commitTxAddressPkScript.toString('hex')}`);
                            throw new Error(`签名错误：花费脚本与预期上下文不匹配`);
                        }

                        // --- 执行签名 --- //
                        const privateKeyForSigning = inscriptionCtx.privateKey; // 使用上下文中的原始私钥
                        const scriptHashForSigning = inscriptionCtx.hash; // TapHash
                        const witnessForSigning = inscriptionCtx.witness; // Witness (不含签名)

                        // 计算 P2TR 签名哈希 (SIGHASH_DEFAULT)
                        const hash = tx.hashForWitnessV1(inputIndex, [prevOutScript], [value], bitcoin.Transaction.SIGHASH_DEFAULT, scriptHashForSigning);
                        // 使用 Schnorr 签名
                        const signature = Buffer.from(schnorr.sign(hash, privateKeyForSigning, base.randomBytes(32)));
                        // 组合最终的 Witness
                        tx.ins[inputIndex].witness = [Buffer.from(signature), ...witnessForSigning];

                        // 更新 prevTxOutputs 以供下一个循环使用
                        prevTxOutputs = tx.outs;
                    }
                } catch (e: any) {
                     console.error(`签名错误 (链 ${chainIndex}, TX ${txIndex}): ${e.message}`);
                     throw new Error(`签名错误 (链 ${chainIndex}, TX ${txIndex}): ${e.message}`);
                }
            });
        });
    }
}

/**
 * @description (复制自 inscribe.ts) 创建单个铭文的交易上下文数据。
 * @param network - 比特币网络配置。
 * @param inscriptionData - 铭文数据。
 * @param privateKeyWif - 用于生成内部公钥和 P2TR 地址的私钥 (WIF 格式)。
 * @returns {InscriptionTxCtxData} - 铭文交易上下文。
 */
function createInscriptionTxCtxData(network: bitcoin.Network, inscriptionData: InscriptionData, privateKeyWif: string): InscriptionTxCtxData {
    const privateKey = base.fromHex(privateKeyFromWIF(privateKeyWif, network)); // WIF 转 Buffer
    const internalPubKey = wif2Public(privateKeyWif, network).slice(1); // 获取 x-only 公钥
    const ops = bitcoin.script.OPS;

    // --- 构建铭文脚本 --- //
    // 结构: <internalPubKey> OP_CHECKSIG OP_FALSE OP_IF <protocol_id> <content_type_tag> <content_type> <body_tag> <body_chunk_1> ... <body_chunk_n> OP_ENDIF
    const inscriptionBuilder: bitcoin.payments.StackElement[] = [];
    inscriptionBuilder.push(internalPubKey);
    inscriptionBuilder.push(ops.OP_CHECKSIG);
    inscriptionBuilder.push(ops.OP_FALSE);
    inscriptionBuilder.push(ops.OP_IF);
    inscriptionBuilder.push(Buffer.from("ord")); // 协议标识符
    inscriptionBuilder.push(ops.OP_DATA_1); // content-type tag
    inscriptionBuilder.push(ops.OP_DATA_1); // length of content-type
    inscriptionBuilder.push(Buffer.from(inscriptionData.contentType)); // content-type
    inscriptionBuilder.push(ops.OP_0); // body tag
    // 分块推送 Body 数据 (最大 520 字节/块)
    const maxChunkSize = 520;
    let body = Buffer.from(inscriptionData.body);
    let bodySize = body.length;
    for (let i = 0; i < bodySize; i += maxChunkSize) {
        let end = i + maxChunkSize;
        if (end > bodySize) { end = bodySize; }
        inscriptionBuilder.push(body.slice(i, end));
    }
    inscriptionBuilder.push(ops.OP_ENDIF);
    const inscriptionScript = bitcoin.script.compile(inscriptionBuilder);

    // --- 构建 P2TR Commit 地址和相关数据 --- //
    const scriptTree = { output: inscriptionScript }; // TapTree
    // Redeem script for P2TR
    const redeem = { output: inscriptionScript, redeemVersion: 0xc0 }; // 使用 P2TR 兼容的 redeem version (annex prefix)
    const {output, witness, hash, address} = bitcoin.payments.p2tr({
        internalPubkey: internalPubKey,
        scriptTree,
        redeem,
        network,
    });

    // --- 返回上下文数据 --- //
    return {
        privateKey, // 原始私钥 Buffer
        inscriptionScript, // 完整的铭文脚本
        commitTxAddress: address!, // P2TR Commit 地址
        commitTxAddressPkScript: output!, // Commit 地址的输出脚本
        witness: witness!, // Reveal 时需要的 Witness (不含签名)
        hash: hash!, // TapTree 的 TapHash
        revealTxPrevOutput: { pkScript: Buffer.alloc(0), value: 0 }, // 占位符，在 buildEmptyRevealTx 中填充
        revealPkScript: bitcoin.address.toOutputScript(inscriptionData.revealAddr, network), // 最终接收铭文地址的输出脚本
    };
}

/**
 * @description (复制自 inscribe.ts) 对交易的指定输入进行签名 (支持 Legacy, SegWit Native, SegWit Nested, Taproot)。
 *              此函数在原始 inscribe.ts 中用于多种场景，在 chain_inscribe.ts 中主要用于签名初始 Commit 交易。
 * @param tx - 需要签名的交易对象 (将被修改)。
 * @param commitTxPrevOutputList - 对应的输入 UTXO 信息列表 (需要私钥、地址、金额)。
 * @param network - 比特币网络配置。
 */
function signTx(tx: bitcoin.Transaction, commitTxPrevOutputList: PrevOutput[], network: bitcoin.Network) {
    tx.ins.forEach((input, i) => {
        // 获取输入地址类型
        const addressType = getAddressType(commitTxPrevOutputList[i].address, network);
        // 获取私钥和公钥
        const privateKey = base.fromHex(privateKeyFromWIF(commitTxPrevOutputList[i].privateKey, network));
        const privateKeyHex = base.toHex(privateKey);
        const publicKey = private2public(privateKeyHex);

        if (addressType === 'segwit_taproot') {
            // --- 签名 Taproot 输入 (Key Path Spending) ---
            // 注意：这里的实现是 Key Path Spending，假设 UTXO 是 P2TR 地址且未使用 Script Path。
            // 如果 UTXO 是 Commit 地址 (Script Path Spending)，签名逻辑在 signAllTransactions 中处理。
            const prevOutScripts = commitTxPrevOutputList.map(o => bitcoin.address.toOutputScript(o.address, network));
            const values = commitTxPrevOutputList.map(o => o.amount);
            const hash = tx.hashForWitnessV1(i, prevOutScripts, values, bitcoin.Transaction.SIGHASH_DEFAULT);
            const tweakedPrivKey = taproot.taprootTweakPrivKey(privateKey); // Tweak 私钥
            const signature = Buffer.from(schnorr.sign(hash, tweakedPrivKey, base.randomBytes(32)));
            input.witness = [Buffer.from(signature)]; // Taproot Key Path spending witness 只有签名

        } else if (addressType === 'legacy') {
            // --- 签名 Legacy (P2PKH) 输入 ---
            const prevScript = bitcoin.address.toOutputScript(commitTxPrevOutputList[i].address, network);
            const hash = tx.hashForSignature(i, prevScript, bitcoin.Transaction.SIGHASH_ALL)!;
            const signature = sign(hash, privateKeyHex); // 使用 ECDSA 签名
            const payment = bitcoin.payments.p2pkh({
                signature: bitcoin.script.signature.encode(signature, bitcoin.Transaction.SIGHASH_ALL),
                pubkey: publicKey,
            });
            input.script = payment.input!; // 设置 inputScript

        } else {
            // --- 签名 SegWit Native (P2WPKH) 或 Nested (P2SH-P2WPKH) 输入 ---
            const pubKeyHash = bcrypto.hash160(publicKey);
            // Previous output script (P2PKH script for witness hash calculation)
            const prevOutScript = Buffer.of(0x19, 0x76, 0xa9, 0x14, ...pubKeyHash, 0x88, 0xac);
            const value = commitTxPrevOutputList[i].amount;
            const hash = tx.hashForWitness(i, prevOutScript, value, bitcoin.Transaction.SIGHASH_ALL);
            const signature = sign(hash, privateKeyHex); // 使用 ECDSA 签名
            // 设置 Witness
            input.witness = [
                bitcoin.script.signature.encode(signature, bitcoin.Transaction.SIGHASH_ALL),
                publicKey,
            ];
            // 如果是 Nested SegWit (P2SH-P2WPKH)，还需要设置 redeemScript 到 inputScript
            const redeemScript = Buffer.of(0x16, 0, 20, ...pubKeyHash); // 0x0014<pubKeyHash>
            if (addressType === "segwit_nested") {
                input.script = redeemScript;
            }
        }
    });
}

/**
 * @description (复制自 inscribe.ts) 计算交易输入的签名哈希 (SigHash)。
 * 注意：此函数在当前的 `inscribeChain` 逻辑中未被直接调用，但保留在此以维持从 `inscribe.ts` 复制的完整性。
 * @param tx - 交易对象。
 * @param prevOutFetcher - 输入 UTXO 信息列表 (需要公钥、地址、金额)。
 * @param network - 比特币网络配置。
 * @returns {string[]} - 每个输入的签名哈希 (hex 格式) 列表。
 */
function calculateSigHash(tx: bitcoin.Transaction, prevOutFetcher: PrevOutput[], network: bitcoin.Network): string[] {
    const sigHashList: string[] = [];
    tx.ins.forEach((input, i) => {
         if (!prevOutFetcher[i].publicKey) {
            // 计算签名哈希需要公钥
            throw new Error(`计算签名哈希错误 (输入索引 ${i}): PrevOutput 中缺少 publicKey`);
         }
        const publicKey = base.fromHex(prevOutFetcher[i].publicKey!); // Hex 公钥转 Buffer
        const pkScript = bitcoin.address.toOutputScript(prevOutFetcher[i].address, network);
        const placeholderSignature = Buffer.alloc(64, 0); // 签名占位符
        let sigHash: Buffer;

        if (isP2TR(pkScript)) {
            // --- 计算 Taproot SigHash (SIGHASH_DEFAULT) ---
            const prevOutScripts = prevOutFetcher.map(o => bitcoin.address.toOutputScript(o.address, network));
            const values = prevOutFetcher.map(o => o.amount);
            sigHash = tx.hashForWitnessV1(i, prevOutScripts, values, bitcoin.Transaction.SIGHASH_DEFAULT);
            input.witness = [placeholderSignature]; // 设置占位 witness
        } else if (isP2PKH(pkScript)) {
            // --- 计算 Legacy (P2PKH) SigHash (SIGHASH_ALL) ---
            const prevScript = pkScript; // P2PKH 输出脚本就是 prevScript
            sigHash = tx.hashForSignature(i, prevScript, bitcoin.Transaction.SIGHASH_ALL)!;
            // 设置占位 inputScript
            input.script = bitcoin.payments.p2pkh({ pubkey: publicKey, signature: bitcoin.script.signature.encode(placeholderSignature, bitcoin.Transaction.SIGHASH_ALL) }).input!;
        } else {
            // --- 计算 SegWit (P2WPKH / P2SH-P2WPKH) SigHash (SIGHASH_ALL) ---
            const pubKeyHash = bcrypto.hash160(publicKey);
            const prevOutScript = Buffer.of(0x19, 0x76, 0xa9, 0x14, ...pubKeyHash, 0x88, 0xac); // P2PKH 形式的脚本
            sigHash = tx.hashForWitness(i, prevOutScript, prevOutFetcher[i].amount, bitcoin.Transaction.SIGHASH_ALL);
            // 设置占位 witness
            input.witness = bitcoin.payments.p2wpkh({ pubkey: publicKey, signature: bitcoin.script.signature.encode(placeholderSignature, bitcoin.Transaction.SIGHASH_ALL) }).witness!;
            const redeemScript = Buffer.of(0x16, 0, 20, ...pubKeyHash); // 0x0014<pubKeyHash>
            // 如果是 Nested SegWit，设置占位 inputScript
            if (isP2SHScript(pkScript)) { input.script = redeemScript; }
        }
        sigHashList.push(base.toHex(sigHash));
    });
    return sigHashList;
}

/**
 * @function inscribeChain
 * @description 主函数，用于执行链式铭刻操作。
 *              接收铭刻请求，构建并签名所有必要的交易链，并返回包含交易数据和 RBF 上下文的结果。
 * @param network - 比特币网络配置。
 * @param request - 链式铭刻请求参数。
 * @returns {Promise<object>} - 一个包含操作结果的对象：
 *          - success (boolean): 操作是否成功。
 *          - txChains (string[][]): 构建出的所有交易链的 Hex 字符串数组。
 *          - txChainTxIds (string[][]): 对应的 TxID 数组。
 *          - lastTxDetails (LastTxInfo[]): 每条链最后一个交易的详细信息，用于 RBF。
 *          - totalEstimatedFee (number): 所有交易的总预估费用 (satoshi)。
 *          - error (string | undefined): 如果失败，包含错误信息。
 */
export function inscribeChain(network: bitcoin.Network, request: InscriptionRequest): ChainInscribeResult {
    try {
        // --- 1. 创建工具实例并执行构建和签名 --- //
        const tool = ChainInscriptionTool.newChainInscriptionTool(network, request);

        // --- 2. 准备返回结果 --- //
        const txChainsHex: string[][] = [];       // 存储交易 Hex
        const txChainTxIds: string[][] = [];      // 存储交易 TxID
        const lastTxDetails: LastTxInfo[] = []; // 存储最后一个交易的详细信息 (用于 RBF)

        // --- 3. 遍历构建好的交易链，提取信息 --- //
        tool.txChains.forEach((chain, chainIndex) => {
            const chainHex: string[] = [];
            const chainTxIds: string[] = [];

            // 一条有效的链至少包含 Commit 和 Reveal 两个交易
            if (chain.length < 2) {
                console.warn(`链式铭刻处理警告 (链 ${chainIndex}): 交易数量 (${chain.length}) 少于 2，无法提取 LastTxInfo，此链可能无效。`);
                txChainsHex.push([]); // 保持结构一致性
                txChainTxIds.push([]);
                return; // 跳过对此无效链的 LastTxInfo 处理
            }

            const lastTxIndex = chain.length - 1;
            const lastTx = chain[lastTxIndex];     // 链中最后一个交易 (Reveal)
            const prevTx = chain[lastTxIndex - 1]; // 链中倒数第二个交易 (可能是 Commit 或 Reveal)

            // 提取链中所有交易的 Hex 和 TxID
            chain.forEach((tx) => {
                chainHex.push(tx.toHex());
                chainTxIds.push(tx.getId());
            });

            txChainsHex.push(chainHex);
            txChainTxIds.push(chainTxIds);

            // --- 4. 组装当前链最后一个交易的 LastTxInfo --- //
            const lastTxId = lastTx.getId();
            const lastTxHex = lastTx.toHex();

            // 查找预估费用
            const feeInfo = tool.txFees.find(f => f.chainIndex === chainIndex && f.txIndex === lastTxIndex);
            const lastTxFee = feeInfo ? feeInfo.fee : 0;
            if (!feeInfo) {
                // 如果找不到费用信息，RBF 时可能需要重新估算
                console.warn(`链式铭刻处理警告 (链 ${chainIndex}): 未找到最后一个交易 (索引 ${lastTxIndex}) 的预估费用信息。`);
            }

            // 获取输入信息 (假设 Reveal 交易只有一个输入)
            const inputInfo = lastTx.ins[0];
            const inputTxId = prevTx.getId();    // 输入来自倒数第二个交易
            const inputVout = inputInfo.index;   // 花费的是倒数第二个交易的哪个输出
            // 健全性检查: prevTx 的输出是否存在
            if (inputVout >= prevTx.outs.length) {
                console.error(`链式铭刻处理错误 (链 ${chainIndex}): 最后一个交易尝试花费倒数第二个交易不存在的输出索引 ${inputVout}`);
                // 此处应决定如何处理，可能跳过此链或抛出错误
                return;
            }
            const inputValue = prevTx.outs[inputVout].value; // 输入金额

            // 获取输出信息
            const outputs = lastTx.outs.map(o => ({
                pkScriptHex: o.script.toString('hex'), // 输出脚本 Hex
                value: o.value                     // 输出金额
            }));

            // 获取签名所需的私钥 WIF 和其他上下文信息
            const mappingInfo = tool.chainContextMapping.find(m => m.chainIndex === chainIndex && m.txIndex === lastTxIndex);
            const contextIndex = mappingInfo?.contextIndex;
            let signingPrivateKeyWIF = '';
            let context: InscriptionTxCtxData | undefined;
            let prevInputPkScriptHex = '';
            let tapScriptTreeHashHex = '';
            let revealPkScriptHex = outputs.length > 0 ? outputs[0].pkScriptHex : ''; // Reveal 输出通常是第一个
            let finalChangePkScriptHex = outputs.length > 1 ? outputs[1].pkScriptHex : ''; // 找零输出通常是第二个

            if (contextIndex !== null && contextIndex !== undefined) {
                 context = tool.inscriptionTxCtxDataList[contextIndex];
                 if(context) {
                     // 将上下文中的私钥 Buffer 转回 WIF 格式
                     signingPrivateKeyWIF = private2Wif(context.privateKey, tool.network);
                     prevInputPkScriptHex = context.commitTxAddressPkScript.toString('hex');
                     tapScriptTreeHashHex = context.hash.toString('hex');
                 } else {
                      // 如果找不到上下文，是个严重错误
                      console.error(`链式铭刻处理错误 (链 ${chainIndex}): 无法从列表 (大小 ${tool.inscriptionTxCtxDataList.length}) 中获取索引为 ${contextIndex} 的铭文上下文。`);
                 }
            } else {
                // 如果找不到映射，也是个严重错误
                console.error(`链式铭刻处理错误 (链 ${chainIndex}): 找不到最后一个交易 (索引 ${lastTxIndex}) 的上下文映射信息。`);
            }
            // 如果未能获取 WIF 或 context，RBF 将无法执行
            if (!signingPrivateKeyWIF || !context) {
                console.error(`链式铭刻处理错误 (链 ${chainIndex}): 无法获取最后一个交易签名所需的 WIF 或上下文信息，RBF 将不可用！`);
                // 即使无法进行 RBF，仍然需要返回尽可能多的信息
            }

            // 组装 LastTxInfo 对象
            const detail: LastTxInfo = {
                txId: lastTxId,
                hex: lastTxHex,
                fee: lastTxFee,
                inputTxId: inputTxId,
                inputVout: inputVout,
                inputValue: inputValue,
                outputs: outputs,
                signingPrivateKeyWIF: signingPrivateKeyWIF, // 使用上面获取的 WIF
                finalChangeAddress: request.changeAddress, // 使用原始请求中的找零地址
                network: tool.network, // 使用工具实例中的网络配置
                revealOutValue: request.revealOutValue || DEFAULT_REVEAL_OUT_VALUE, // 使用请求值或默认值
                minChangeValue: request.minChangeValue || DEFAULT_MIN_CHANGE_VALUE, // 使用请求值或默认值
                prevInputPkScriptHex: prevInputPkScriptHex,
                revealPkScriptHex: revealPkScriptHex,
                finalChangePkScriptHex: finalChangePkScriptHex,
                tapScriptTreeHashHex: tapScriptTreeHashHex,
                networkType: tool.network === bitcoin.networks.bitcoin ? 'mainnet' : 'testnet', // 简化判断
            };
            // 在添加前再次检查 RBF 所需信息是否完整
            if (!detail.signingPrivateKeyWIF || !detail.prevInputPkScriptHex || !detail.tapScriptTreeHashHex) {
                console.warn(`链式铭刻处理警告 (链 ${chainIndex}): RBF 所需的 WIF、输入脚本或哈希信息不完整，RBF 功能可能受限。`);
            }
            lastTxDetails.push(detail);
        });

        // --- 5. 返回成功结果 --- //
        return {
            success: true,
            txChains: txChainsHex,
            txChainTxIds: txChainTxIds,
            lastTxDetails: lastTxDetails, // 返回详细的 RBF 信息
            totalEstimatedFee: tool.totalEstimatedFee
        };
    } catch (error: any) {
        // --- 6. 返回失败结果 --- //
        console.error("链式铭刻执行失败:", error);
        // 确保返回结构一致性
        return {
            success: false,
            error: error.message || '未知错误',
            txChains: [],
            txChainTxIds: [],
            lastTxDetails: [],
            totalEstimatedFee: 0
        };
    }
} 