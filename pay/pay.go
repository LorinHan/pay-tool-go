package pay

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/skip2/go-qrcode"
	"github.com/smartwalle/alipay/v3"
	"github.com/wechatpay-apiv3/wechatpay-go/core"
	"github.com/wechatpay-apiv3/wechatpay-go/core/auth/verifiers"
	"github.com/wechatpay-apiv3/wechatpay-go/core/downloader"
	"github.com/wechatpay-apiv3/wechatpay-go/core/notify"
	"github.com/wechatpay-apiv3/wechatpay-go/core/option"
	"github.com/wechatpay-apiv3/wechatpay-go/services/payments"
	"github.com/wechatpay-apiv3/wechatpay-go/services/payments/native"
	"github.com/wechatpay-apiv3/wechatpay-go/utils"
	"log"
	"net/http"
	"strconv"
	"time"
)

/**
 * 支付工具类
 * @author: Lorin
 * @date: 2022/1/26
 * @description: 先调用 Init(*InitOption) 对支付宝/微信支付进行初始化，然后可通过 Get(Mode) 获取对应的支付工具
 * Pay interface 支付工具，具有三个函数：Pay 支付；Notify 回调接收；AckNotification 回调应答；OrderQuery 订单查询
 * Url封二维码 UrlToQrCode；人民币金额分转元 CentsToYuan
 */

var (
	wxPay  Pay
	aliPay Pay
)

type Pay interface {
	init(initOption *InitOption) error
	// Pay 支付；返回一串url，支付宝的url可直接浏览器访问进行支付，微信的url在微信手机客户端可以点击支付，但一般都是封成二维码进行扫描
	Pay(params *WebPayParam) (string, error)
	// Notify 通知回调; 接收支付宝/微信支付成功后的回调，返回 NotifyResp 回调参数内容
	Notify(req *http.Request) (*NotifyResp, error)
	// AckNotification 应答回调通知，收到回调后，正常情况需进行响应，否则支付平台将按照相应规则重发回调
	AckNotification(writer http.ResponseWriter)
	// OrderQuery 订单查询
	OrderQuery(orderNum string) (*OrderQueryResp, error)
}

// WebPayParam 支付参数
type WebPayParam struct {
	Subject     string    // 支付标题
	OutTradeNo  string    // 自定义订单号
	ReturnUrl   string    // 支付完成跳转地址，仅对支付宝web有效
	TotalAmount int64     // 总金额，以分为单位
	TimeExpire  time.Time // 订单超时时间
}

type wxPayHelper struct {
	appID                      string
	mchID                      string
	notifyUrl                  string
	mchCertificateSerialNumber string
	mchAPIv3Key                string
	mchPrivateKey              *rsa.PrivateKey
	svc                        *native.NativeApiService
}

type InitOption struct {
	WxPayOption  *WxPayOption
	AliPayOption *AliPayOption
}

type WxPayOption struct {
	PrivateKeyPath             string
	AppID                      string
	MchID                      string
	NotifyUrl                  string
	MchCertificateSerialNumber string
	MchAPIv3Key                string
}

type AliPayOption struct {
	AppID                string
	PrivateKey           string
	IsProduction         bool   // 是否为生产环境
	AppPublicCertFile    string // 应用公钥证书
	AliPayRootCertFile   string // 支付宝根证书
	AliPayPublicCertFile string // 支付宝公钥证书
	NotifyUrl            string
}

type aliPayHelper struct {
	client    *alipay.Client
	notifyUrl string
}

type OrderQueryResp struct {
	AliOrder *alipay.TradeQueryRsp
	WxOrder  *payments.Transaction
}

type NotifyResp struct {
	AliPayResp *alipay.TradeNotification
	WxPayResp  *WxPayResp
}

type WxPayResp struct {
	*notify.Request
	*payments.Transaction
}

func (a *aliPayHelper) init(initOption *InitOption) error {
	var (
		err     error
		options = initOption.AliPayOption
	)

	a.client, err = alipay.New(options.AppID, options.PrivateKey, options.IsProduction)
	if err != nil {
		return err
	}

	// 加载应用公钥证书
	if err = a.client.LoadAppPublicCertFromFile("crts/appCertPublicKey_2016101500691847.crt"); err != nil {
		return err
	}
	// 加载支付宝根证书
	if err = a.client.LoadAliPayRootCertFromFile("crts/alipayRootCert.crt"); err != nil {
		return err
	}
	// 加载支付宝公钥证书
	if err = a.client.LoadAliPayPublicCertFromFile("crts/alipayCertPublicKey_RSA2.crt"); err != nil {
		return err
	}

	a.notifyUrl = initOption.AliPayOption.NotifyUrl
	return nil
}

func (a *aliPayHelper) Pay(params *WebPayParam) (string, error) {
	fmt.Println(params)
	pay := alipay.TradePagePay{}
	// 支付宝回调地址（需要在支付宝后台配置），支付成功后，支付宝会发送一个POST消息到该地址
	pay.NotifyURL = a.notifyUrl
	// 支付成功之后，浏览器将会重定向到该 URL
	pay.ReturnURL = params.ReturnUrl
	// 支付标题
	pay.Subject = params.Subject
	// 订单号，一个订单号只能支付一次
	pay.OutTradeNo = params.OutTradeNo
	// 销售产品码，与支付宝签约的产品码名称,目前仅支持FAST_INSTANT_TRADE_PAY
	pay.ProductCode = "FAST_INSTANT_TRADE_PAY"
	// 金额
	pay.TotalAmount = CentsToYuan(params.TotalAmount)
	// 订单超时时间
	// pay.TimeExpire = params.TimeExpire.Format(DATE_FORMAT)
	// pay.TimeExpire = "2022-01-27 11:02:02"

	url, err := a.client.TradePagePay(pay)
	if err != nil {
		return "", err
	}

	// 这个 url 即是用于支付的 URL，可将输出的内容复制，到浏览器中访问该 URL 即可打开支付页面。
	return url.String(), nil
}

func (a *aliPayHelper) Notify(req *http.Request) (*NotifyResp, error) {
	resp, err := a.client.GetTradeNotification(req)
	if err != nil {
		return nil, err
	}
	return &NotifyResp{AliPayResp: resp}, nil
}

func (a *aliPayHelper) AckNotification(writer http.ResponseWriter) {
	alipay.AckNotification(writer)
}

func (a *aliPayHelper) OrderQuery(orderNum string) (*OrderQueryResp, error) {
	p := alipay.TradeQuery{}
	p.OutTradeNo = orderNum
	resp, err := a.client.TradeQuery(p)
	if err != nil {
		return nil, err
	}
	return &OrderQueryResp{
		AliOrder: resp,
	}, nil
}

func (w *wxPayHelper) OrderQuery(orderNum string) (*OrderQueryResp, error) {
	resp, _, err := w.svc.QueryOrderByOutTradeNo(context.Background(), native.QueryOrderByOutTradeNoRequest{
		OutTradeNo: &orderNum,
		Mchid:      &w.mchID,
	})
	if err != nil {
		return nil, err
	}
	return &OrderQueryResp{
		WxOrder: resp,
	}, nil
}

func (w *wxPayHelper) init(initOption *InitOption) error {
	var (
		err     error
		options = initOption.WxPayOption
	)
	// 使用 utils 提供的函数从本地文件中加载商户私钥，商户私钥会用来生成请求的签名
	w.mchPrivateKey, err = utils.LoadPrivateKeyWithPath(options.PrivateKeyPath)
	if err != nil {
		return err
	}

	ctx := context.Background()
	// 使用商户私钥等初始化 client，并使它具有自动定时获取微信支付平台证书的能力
	opts := []core.ClientOption{
		option.WithWechatPayAutoAuthCipher(options.MchID, options.MchCertificateSerialNumber, w.mchPrivateKey, options.MchAPIv3Key),
	}
	client, err := core.NewClient(ctx, opts...)
	if err != nil {
		return err
	}

	w.svc = &native.NativeApiService{
		Client: client,
	}
	w.appID = options.AppID
	w.mchID = options.MchID
	w.notifyUrl = options.NotifyUrl
	w.mchAPIv3Key = options.MchAPIv3Key
	w.mchCertificateSerialNumber = options.MchCertificateSerialNumber

	return nil
}

func (w *wxPayHelper) Pay(params *WebPayParam) (string, error) {
	resp, _, err := w.svc.Prepay(context.Background(), native.PrepayRequest{
		Appid:       &w.appID,
		Mchid:       &w.mchID,
		NotifyUrl:   &w.notifyUrl,
		Description: &params.Subject,
		OutTradeNo:  &params.OutTradeNo,
		TimeExpire:  &params.TimeExpire,
		Amount:      &native.Amount{Total: &params.TotalAmount},
	})
	if err != nil {
		return "", err
	}

	return *resp.CodeUrl, nil
}

func (w *wxPayHelper) Notify(req *http.Request) (*NotifyResp, error) {
	ctx := context.Background()
	// 1. 使用 `RegisterDownloaderWithPrivateKey` 注册下载器
	if err := downloader.MgrInstance().RegisterDownloaderWithPrivateKey(ctx, w.mchPrivateKey, w.mchCertificateSerialNumber, w.mchID, w.mchAPIv3Key); err != nil {
		return nil, err
	}
	// 2. 获取商户号对应的微信支付平台证书访问器
	certVisitor := downloader.MgrInstance().GetCertificateVisitor(w.mchID)
	// 3. 使用证书访问器初始化 `notify.Handler`
	handler := notify.NewNotifyHandler(w.mchAPIv3Key, verifiers.NewSHA256WithRSAVerifier(certVisitor))

	transaction := new(payments.Transaction)
	notifyReq, err := handler.ParseNotifyRequest(context.Background(), req, transaction)
	// 如果验签未通过，或者解密失败
	if err != nil {
		return nil, err
	}
	return &NotifyResp{
		WxPayResp: &WxPayResp{
			Request:     notifyReq,
			Transaction: transaction,
		},
	}, nil
}

func (w *wxPayHelper) AckNotification(writer http.ResponseWriter) {
	writer.WriteHeader(http.StatusOK)
	ack := map[string]string{"code": "SUCCESS", "message": "成功"}
	ackBytes, err := json.Marshal(ack)
	if err != nil {
		log.Println(err)
	}
	if _, err = writer.Write(ackBytes); err != nil {
		log.Println(err)
	}
}

func Init(ali, wx bool, options *InitOption) error {
	if ali {
		aliPay = &aliPayHelper{}
		if err := aliPay.init(options); err != nil {
			return err
		}
	}
	if wx {
		wxPay = &wxPayHelper{}
		if err := wxPay.init(options); err != nil {
			return err
		}
	}

	return nil
}

// Mode 支付类型
type Mode int

const (
	DATE_FORMAT       = "2006-01-02 15:00:00"
	ALI_PAY_MODE Mode = iota
	WX_PAY_MODE
)

// Get 支付工具获取；mode 支付工具类型：AliPayMode(支付宝), WxPayMode(微信支付)
func Get(mode Mode) Pay {
	switch mode {
	case ALI_PAY_MODE:
		return aliPay
	case WX_PAY_MODE:
		return wxPay
	default:
		return nil
	}
}

// CentsToYuan 金额分转元，1分(int64)转为0.01元(字符串)
func CentsToYuan(cents int64) string {
	var (
		yuan, jiao, fen string
	)

	temp := strconv.FormatInt(cents, 10)
	tempLen := len(temp)
	if tempLen >= 3 {
		yuan = temp[:tempLen-2]
	}
	if tempLen >= 2 {
		jiao = temp[len(yuan) : tempLen-1]
	}
	fen = temp[tempLen-1:]

	if yuan == "" {
		yuan = "0"
	}
	if jiao == "" {
		jiao = "0"
	}
	return fmt.Sprintf("%s.%s%s", yuan, jiao, fen)
}

// UrlToQrCode 将url封为二维码图片；url：访问路径；level：二维码质量等级(qrcode.Low, qrcode.Medium, qrcode.High, qrcode.Highest)；size：二维码尺寸；
func UrlToQrCode(url string, level qrcode.RecoveryLevel, size int) ([]byte, error) {
	return qrcode.Encode(url, level, size)
}
