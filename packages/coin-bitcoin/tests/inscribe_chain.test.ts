import * as bitcoin from "../src";
import {
    // 导入链式铭刻相关
    inscribeChain,
    InscriptionData,
    InscriptionRequest,
    networks,
    PrevOutput,
    ChainInscribeResult,
    LastTxInfo as ChainLastTxInfo,
    // MAX_TRANSACTIONS_PER_CHAIN, // 不再从外部导入
    // DEFAULT_MIN_CHANGE_VALUE // 不再从外部导入
} from "../src"; // 从 src/index.ts 导入

// 在测试文件中定义常量，与 inscribe_chain.ts 保持一致
const MAX_TRANSACTIONS_PER_CHAIN = 25;
const DEFAULT_MIN_CHANGE_VALUE = 546;
const DEFAULT_REVEAL_OUT_VALUE = 546; // 也定义这个，以防万一

describe("brc20 chain inscription tests", () => {
    const network = networks.testnet;
    // 使用文件中已有的测试 WIF
    const testWif = "cPnvkvUYyHcSSS26iD1dkrJdV7k1RoUqJLhn3CYxpo398PdLVE22";
    // TODO: 替换为与 WIF 对应的有效测试网地址 (例如 P2WPKH 或 P2TR)
    const testAddress = "tb1pdlc2c37vlaulc042krxsq37z3h4djhxnt3kxjh07xvqshzq869kqz5sgrc"; // 示例地址，需要确认是否与 testWif 匹配
    // TODO: 替换为有效的测试网接收地址
    const revealAddress = "tb1pklh8lqax5l7m2ycypptv2emc4gata2dy28svnwcp9u32wlkenvsspcvhsr";
    // TODO: 替换为有效的测试网找零地址
    const changeAddress = "tb1pklh8lqax5l7m2ycypptv2emc4gata2dy28svnwcp9u32wlkenvsspcvhsr";

    test("inscribeChain should create multiple chains from multiple UTXOs", async () => { // 重命名测试描述以更准确
        // 准备两个 UTXO
        // UTXO 1: 用于前 24 个铭文
        const utxoAmount1 = 50000; // 足以支付 24 个铭文的费用
        // UTXO 2: 用于后 6 个铭文
        const utxoAmount2 = 10000; // 足以支付 6 个铭文的费用
        const commitTxPrevOutputList: PrevOutput[] = [
            {
                txId: "831735bbc26229cdb3665a491378c0fd4047c366521492825aa20c5d180656a5", // 示例 TxID 1
                vOut: 0,
                amount: utxoAmount1,
                address: testAddress,
                privateKey: testWif,
            },
            {
                txId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 示例 TxID 2 (需替换为有效或模拟的)
                vOut: 1, // 示例 vOut
                amount: utxoAmount2,
                address: testAddress, // 假设用同一地址和私钥
                privateKey: testWif,
            },
        ];

        // 准备 30 个铭文数据 (保持不变)
        const inscriptionCount = 30;
        const inscriptionDataList: InscriptionData[] = [];
        for (let i = 0; i < inscriptionCount; i++) {
            inscriptionDataList.push({
                contentType: "text/plain;charset=utf-8",
                body: `{"p":"brc-20","op":"mint","tick":"test","amt":"1","nonce":"${i}"}`, // 添加 nonce 确保唯一性
                revealAddr: revealAddress,
            });
        }

        const request: InscriptionRequest = {
            commitTxPrevOutputList,
            commitFeeRate: 2.0, // 示例费率
            revealFeeRate: 2.5, // 示例费率
            revealOutValue: 546,
            inscriptionDataList,
            changeAddress: changeAddress,
            minChangeValue: 546
        };

        // 执行链式铭刻
        const result: ChainInscribeResult = inscribeChain(network, request);
        console.log("Chain Inscription (Multiple UTXOs) Result:", JSON.stringify(result, null, 2));

        // 断言结果 (期望成功并有两条链)
        expect(result.success).toBe(true);
        expect(result.error).toBeUndefined();
        expect(result.txChains).toBeDefined();
        expect(result.txChainTxIds).toBeDefined();
        expect(result.lastTxDetails).toBeDefined();
        expect(result.totalEstimatedFee).toBeGreaterThan(0);

        // 检查是否生成了正确的链数量 (顺序填充策略: 1 UTXO -> 24 inscriptions, then next UTXO)
        const maxInscriptionsPerChain = MAX_TRANSACTIONS_PER_CHAIN - 1;
        const expectedChainCount = Math.ceil(inscriptionCount / maxInscriptionsPerChain); // 30 / 24 = 2
        expect(result.txChains.length).toBe(expectedChainCount);
        expect(result.txChainTxIds.length).toBe(expectedChainCount);
        expect(result.lastTxDetails.length).toBe(expectedChainCount);

        // 检查第一条链的交易数量 (1 Commit + 24 Reveals = 25)
        expect(result.txChains[0].length).toBe(1 + maxInscriptionsPerChain);
        expect(result.txChainTxIds[0].length).toBe(1 + maxInscriptionsPerChain);

        // 检查第二条链的交易数量 (1 Commit + 6 Reveals = 7)
        const remainingInscriptions = inscriptionCount - maxInscriptionsPerChain;
        expect(result.txChains[1].length).toBe(1 + remainingInscriptions);
        expect(result.txChainTxIds[1].length).toBe(1 + remainingInscriptions);

        // 检查 LastTxInfo
        result.lastTxDetails.forEach((detail: ChainLastTxInfo, index: number) => {
            expect(detail.txId).toBeDefined();
            expect(detail.hex).toBeDefined();
            expect(detail.fee).toBeGreaterThanOrEqual(0);
            expect(detail.inputTxId).toBeDefined();
            expect(detail.inputVout).toBeDefined();
            expect(detail.inputValue).toBeGreaterThan(0);
            expect(detail.outputs).toBeDefined();
            expect(detail.signingPrivateKeyWIF).toBe(testWif); // 确认签名私钥是正确的 - 两个链都用同一个
            expect(detail.finalChangeAddress).toBe(changeAddress);
            expect(detail.network).toBe(network);
            expect(detail.revealOutValue).toBe(request.revealOutValue);
            expect(detail.minChangeValue).toBe(request.minChangeValue || DEFAULT_MIN_CHANGE_VALUE);
            expect(detail.prevInputPkScriptHex).toBeDefined();
            expect(detail.revealPkScriptHex).toBeDefined();
            expect(detail.tapScriptTreeHashHex).toBeDefined();
            expect(detail.networkType).toBe('testnet');
        });
    });

    test("inscribeChain should fail if UTXO count is insufficient for required chains", async () => { // 添加新测试或调整现有失败测试的描述
        // 这个测试验证当 UTXO 数量不足以启动所有必需链时的失败情况
        const commitTxPrevOutputList: PrevOutput[] = [
             {
                // 只提供一个 UTXO，但需要两个链
                txId: "831735bbc26229cdb3665a491378c0fd4047c366521492825aa20c5d180656a5", // 即使金额足够
                vOut: 0,
                amount: 250000, // 金额足够
                address: testAddress,
                privateKey: testWif,
            },
        ];

        const inscriptionCount = 30; // 需要两条链
        const inscriptionDataList: InscriptionData[] = [];
        for (let i = 0; i < inscriptionCount; i++) {
             inscriptionDataList.push({
                contentType: "text/plain;charset=utf-8",
                body: `{"p":"brc-20","op":"mint","tick":"fail_count","amt":"1","nonce":"${i}"}`,
                revealAddr: revealAddress,
            });
        }

         const request: InscriptionRequest = {
            commitTxPrevOutputList,
            commitFeeRate: 2.0,
            revealFeeRate: 2.5,
            revealOutValue: 546,
            inscriptionDataList,
            changeAddress: changeAddress,
            minChangeValue: 546
        };

        const result: ChainInscribeResult = inscribeChain(network, request);
        console.log("Insufficient UTXO Count Result:", JSON.stringify(result, null, 2));

        expect(result.success).toBe(false); // 期望失败
        expect(result.error).toBeDefined();
        expect(result.error).toMatch(/UTXO 数量 \(1\) 不足以处理所有铭文 \(30\)/); // 明确检查 UTXO 数量不足的错误
        expect(result.txChains.length).toBe(0); // 不应生成任何完整的链
        expect(result.txChainTxIds.length).toBe(0);
        expect(result.lastTxDetails.length).toBe(0);
        expect(result.totalEstimatedFee).toBe(0);
     });

    test("inscribeChain should fail if UTXO value is insufficient", async () => {
        // 这个测试验证当 UTXO 金额不足以支付所有铭文费用时的失败情况
        const commitTxPrevOutputList: PrevOutput[] = [
            {
                txId: "831735bbc26229cdb3665a491378c0fd4047c366521492825aa20c5d180656a5", // 示例 TxID
                vOut: 0,
                amount: 1000, // 金额不足
                address: testAddress,
                privateKey: testWif,
            },
        ];

        const inscriptionDataList: InscriptionData[] = [
             {
                contentType: "text/plain;charset=utf-8",
                body: `{"p":"brc-20","op":"mint","tick":"fail_value","amt":"1"}`,
                revealAddr: revealAddress,
            }
        ];

         const request: InscriptionRequest = {
            commitTxPrevOutputList,
            commitFeeRate: 2.0,
            revealFeeRate: 2.5,
            revealOutValue: 546,
            inscriptionDataList,
            changeAddress: changeAddress,
            minChangeValue: 546
        };

        const result: ChainInscribeResult = inscribeChain(network, request);
        console.log("Insufficient UTXO Value Result:", JSON.stringify(result, null, 2));

        expect(result.success).toBe(false);
        expect(result.error).toBeDefined();
        expect(result.error).toMatch(/交易链中断，余额.*?不足以支付 Reveal 费用/); // 更新了正则表达式以匹配更具体的错误消息
        expect(result.txChains.length).toBe(0);
        expect(result.txChainTxIds.length).toBe(0);
        expect(result.lastTxDetails.length).toBe(0);
        expect(result.totalEstimatedFee).toBe(0);
    });

    // ... (可以添加更多测试用例) ...

}); 