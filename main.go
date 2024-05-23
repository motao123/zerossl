package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/imroc/req/v3"
	"github.com/manifoldco/promptui"
)

func main() {
	// 信息输入
	promptUsername := promptui.Prompt{
		Label: "请输入用户名",
	}
	username, err := promptUsername.Run()
	if err != nil {
		fmt.Printf("输入用户名时出错: %v\n", err)
		return
	}

	promptPassword := promptui.Prompt{
		Label: "请输入密码",
		Mask:  '*',
	}
	password, err := promptPassword.Run()
	if err != nil {
		fmt.Printf("输入密码时出错: %v\n", err)
		return
	}

	promptDomain := promptui.Prompt{
		Label: "请输入泛域名",
	}
	domain, err := promptDomain.Run()
	if err != nil {
		fmt.Printf("输入域名时出错: %v\n", err)
		return
	}

	promptSelect := promptui.Select{
		Label: "选择证书类型",
		Items: []string{"ECC", "RSA"},
	}
	_, cert, err := promptSelect.Run()
	if err != nil {
		fmt.Printf("选择证书类型时出错: %v\n", err)
		return
	}

	// sha256 密码
	password = fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
	// 生成 csr 和私钥
	var csr, pk []byte
	switch cert {
	case "ECC":
		csr, pk, err = GenerateECDSA(domain)
	case "RSA":
		csr, pk, err = GenerateRSA(domain)
	default:
		fmt.Println("未知的证书类型")
		return
	}
	if err != nil {
		fmt.Printf("生成 csr 和私钥时出错: %v\n", err)
		return
	}

	fmt.Println("私钥:")
	fmt.Println(string(pk))

	// 开始登录流程
	client := req.C()
	client.ImpersonateChrome()
	client.SetBaseURL("https://app.zerossl.com")

	data := map[string]string{
		"email_address": username,
		"password":      password,
	}
	encode, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("编码数据时出错: %v\n", err)
		return
	}

	resp, err := client.R().
		SetQueryParams(map[string]string{
			"type": "sign_in",
		}).
		SetFormData(map[string]string{
			"postArray": string(encode),
		}).
		Post("/ajax/public_ajax_handler.php?type=sign_in")

	if err != nil {
		fmt.Printf("登录时出错: %v\n", err)
		return
	}

	// 获取 _cpt cookie
	cpt := ""
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "_cpt" {
			cpt = cookie.Value
			break
		}
	}
	if cpt == "" {
		fmt.Println("获取 _cpt cookie 失败")
		return
	}

	fmt.Println("初始化成功")

	// 订阅计划
	data = map[string]string{
		"plan_id":           "512",
		"payment_frequency": "monthly",
	}
	encode, _ = json.Marshal(data)
	resp, err = client.R().
		SetQueryParams(map[string]string{
			"type": "change_subscription_plan",
			"_cpt": cpt,
		}).
		SetFormData(map[string]string{
			"postArray": string(encode),
		}).
		Post("/ajax/advanced_ajax_handler.php")
	if err != nil {
		fmt.Printf("订阅计划时出错: %v\n", err)
		return
	}

	// 降级计划
	data = map[string]string{
		"plan_id":           "477",
		"payment_frequency": "monthly",
	}
	encode, _ = json.Marshal(data)
	resp, err = client.R().
		SetQueryParams(map[string]string{
			"type": "change_subscription_plan",
			"_cpt": cpt,
		}).
		SetFormData(map[string]string{
			"postArray": string(encode),
		}).
		Post("/ajax/advanced_ajax_handler.php")
	if err != nil {
		fmt.Printf("降级计划时出错: %v\n", err)
		return
	}

	fmt.Println("订阅计划修改成功")

	// 取用户 token
	token := ""
	resp, err = client.R().
		SetQueryParams(map[string]string{
			"is_ajax": "1",
			"page":    "developer",
		}).
		Get("/pages/developer.php")
	if err != nil {
		fmt.Printf("获取用户 token 时出错: %v\n", err)
		return
	}
	match := regexp.MustCompile(`<span>([a-f0-9]{32})</span>`).FindStringSubmatch(resp.String())
	if len(match) != 2 {
		fmt.Println("匹配用户 token 失败")
		return
	}
	token = match[1]

	// 提交证书请求
	data = map[string]string{
		"certificate_domains":       domain,
		"certificate_validity_days": "365",
		"certificate_csr":           string(csr),
		"strict_domains":            "1",
	}
	encode, _ = json.Marshal(data)
	resp, err = client.R().
		SetQueryParam("access_key", token).
		SetBodyJsonMarshal(data).
		Post("https://api.zerossl.com/certificates")
	if err != nil {
		fmt.Printf("提交证书请求时出错: %v\n", err)
		return
	}

	fmt.Println("证书请求提交成功，请前往 ZeroSSL 官网验证域名")
	fmt.Println("保存好私钥后可以关闭本程序")

	select {}
}
