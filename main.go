package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"
	"log"
	"net/http"
	"pay-tool-go/pay"
	"strconv"
	"time"
)

const (
	aliAppID       = ""
	aliPrivateKey  = ""
	aliAppPubCert  = "crts/appCertPublicKey_2016101500691847.crt"
	aliPayRootCert = "crts/alipayRootCert.crt"
	aliPayPubCert  = "crts/alipayCertPublicKey_RSA2.crt"
	aliNotifyUrl   = ""

	wxPrivateKeyPath   = "crts/wx_apiclient_key.pem"
	wxAppID            = ""
	wxMchID            = ""
	wxNotifyUrl        = ""
	wxMchCertSerialNum = ""
	wxV3Key            = ""
)

func main() {
	if err := pay.Init(true, true, &pay.InitOption{
		AliPayOption: &pay.AliPayOption{
			AppID:                aliAppID,
			PrivateKey:           aliPrivateKey,
			IsProduction:         false,
			AppPublicCertFile:    aliAppPubCert,
			AliPayRootCertFile:   aliPayRootCert,
			AliPayPublicCertFile: aliPayPubCert,
			NotifyUrl:            aliNotifyUrl,
		},
		WxPayOption: &pay.WxPayOption{
			PrivateKeyPath:             wxPrivateKeyPath,
			AppID:                      wxAppID,
			MchID:                      wxMchID,
			NotifyUrl:                  wxNotifyUrl,
			MchCertificateSerialNumber: wxMchCertSerialNum,
			MchAPIv3Key:                wxV3Key,
		},
	}); err != nil {
		log.Fatal("支付工具初始化失败：", err)
	}

	r := gin.Default()
	r.GET("/alipay", func(c *gin.Context) {
		aliPay := pay.Get(pay.ALI_PAY_MODE)
		url, err := aliPay.Pay(&pay.WebPayParam{
			Subject:     "支付宝测试",
			OutTradeNo:  strconv.FormatInt(time.Now().Unix(), 10),
			ReturnUrl:   "http://localhost:13661/return",
			TotalAmount: 1,
			TimeExpire:  time.Now().Add(time.Hour * 24 * 3),
		})
		if err != nil {
			c.JSON(200, gin.H{
				"message": err,
			})
			return
		}
		c.Writer.WriteString(url)
	})

	r.GET("/return", func(ctx *gin.Context) {
		ctx.Request.ParseForm()
		var outTradeNo = ctx.Request.Form.Get("out_trade_no")

		ctx.String(http.StatusOK, "订单 %s 支付成功", outTradeNo)
	})

	r.GET("/wxpay", func(ctx *gin.Context) {
		url, err := pay.Get(pay.WX_PAY_MODE).Pay(&pay.WebPayParam{
			Subject:     "微信支付测试",
			OutTradeNo:  strconv.FormatInt(time.Now().Unix(), 10),
			TotalAmount: 1,
			TimeExpire:  time.Now().Add(time.Hour * 24 * 3),
		})
		if err != nil {
			ctx.JSON(200, gin.H{
				"code":    -1,
				"message": err,
			})
			return
		}
		qrCode, err := pay.UrlToQrCode(url, qrcode.Medium, 512)
		if err != nil {
			ctx.JSON(200, gin.H{
				"code":    -1,
				"message": err,
			})
			return
		}
		ctx.Writer.Write(qrCode)
	})

	r.POST("/aihc/pay", func(ctx *gin.Context) {
		wxPay := pay.Get(pay.WX_PAY_MODE)
		notify, err := wxPay.Notify(ctx.Request)
		if err != nil {
			fmt.Println("ali notify err:", err)
			return
		}
		fmt.Println("交易状态为:", *notify.WxPayResp.TradeState)
		fmt.Println("event_type：", notify.WxPayResp.EventType)
		fmt.Println("订单号：", *notify.WxPayResp.TransactionId)
		fmt.Println(*notify.WxPayResp)
		wxPay.AckNotification(ctx.Writer)
	})

	r.POST("/aihc/pay/ali", func(ctx *gin.Context) {
		aliPay := pay.Get(pay.ALI_PAY_MODE)
		notify, err := aliPay.Notify(ctx.Request)
		if err != nil {
			fmt.Println("ali notify err:", err)
			return
		}
		fmt.Println("交易状态为:", notify.AliPayResp.TradeStatus)
		fmt.Println("订单号：", notify.AliPayResp.TradeNo)
		fmt.Println(*notify.AliPayResp)
		aliPay.AckNotification(ctx.Writer)
	})

	r.GET("/order", func(ctx *gin.Context) {
		mode := ctx.Query("mode")
		orderNum := ctx.Query("orderNum")

		if mode == "wx" {
			order, err := pay.Get(pay.WX_PAY_MODE).OrderQuery(orderNum)
			if err != nil {
				ctx.JSON(200, gin.H{
					"code":    -1,
					"message": err,
				})
				return
			}
			ctx.JSON(200, gin.H{
				"code":    0,
				"message": "success",
				"data":    order.WxOrder,
			})
		} else {
			order, err := pay.Get(pay.ALI_PAY_MODE).OrderQuery(orderNum)
			if err != nil {
				ctx.JSON(200, gin.H{
					"code":    -1,
					"message": err,
				})
				return
			}
			fmt.Println(order.AliOrder.IsSuccess())
			ctx.JSON(200, gin.H{
				"code":    0,
				"message": "success",
				"data":    order.AliOrder,
			})
		}
	})

	r.Run(":13661")
}
