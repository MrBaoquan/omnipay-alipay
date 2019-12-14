<?php

namespace Omnipay\Alipay;

use Omnipay\Alipay\Requests\AopCompletePurchaseRequest;
use Omnipay\Alipay\Requests\AopCompleteRefundRequest;
use Omnipay\Alipay\Requests\AopTradeCancelRequest;
use Omnipay\Alipay\Requests\AopTradeCloseRequest;
use Omnipay\Alipay\Requests\AopTradeOrderSettleRequest;
use Omnipay\Alipay\Requests\AopTradeQueryRequest;
use Omnipay\Alipay\Requests\AopTradeRefundQueryRequest;
use Omnipay\Alipay\Requests\AopTradeRefundRequest;
use Omnipay\Alipay\Requests\AopTransferToAccountQueryRequest;
use Omnipay\Alipay\Requests\AopTransferToAccountRequest;
use Omnipay\Alipay\Requests\DataServiceBillDownloadUrlQueryRequest;
use Omnipay\Common\AbstractGateway;
use Omnipay\Common\Exception\InvalidRequestException;
use Omnipay\Common\Message\AbstractRequest;

abstract class AbstractAopGateway extends AbstractGateway
{
    protected $endpoints = [
        'production' => 'https://openapi.alipay.com/gateway.do',
        'sandbox'    => 'https://openapi.alipaydev.com/gateway.do',
    ];


    public function getDefaultParameters()
    {
        return [
            'format'    => 'JSON',
            'charset'   => 'UTF-8',
            'signType'  => 'RSA',
            'version'   => '1.0',
            'timestamp' => date('Y-m-d H:i:s'),
            'alipaySdk' => 'lokielse/omnipay-alipay',
        ];
    }


    /**
     * @return mixed
     */
    public function getAppId()
    {
        return $this->getParameter('app_id');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setAppId($value)
    {
        return $this->setParameter('app_id', $value);
    }


    /**
     * @return mixed
     */
    public function getFormat()
    {
        return $this->getParameter('format');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setFormat($value)
    {
        return $this->setParameter('format', $value);
    }


    /**
     * @return mixed
     */
    public function getCharset()
    {
        return $this->getParameter('charset');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setCharset($value)
    {
        return $this->setParameter('charset', $value);
    }


    /**
     * @return mixed
     */
    public function getSignType()
    {
        return $this->getParameter('sign_type');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setSignType($value)
    {
        return $this->setParameter('sign_type', $value);
    }


    /**
     * @return mixed
     */
    public function getVersion()
    {
        return $this->getParameter('version');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setVersion($value)
    {
        return $this->setParameter('version', $value);
    }


    /**
     * @return mixed
     */
    public function getPrivateKey()
    {
        return $this->getParameter('private_key');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setPrivateKey($value)
    {
        return $this->setParameter('private_key', $value);
    }


    /**
     * @return mixed
     */
    public function getEncryptKey()
    {
        return $this->getParameter('encrypt_key');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setEncryptKey($value)
    {
        return $this->setParameter('encrypt_key', $value);
    }


    /**
     * @return mixed
     */
    public function getNotifyUrl()
    {
        return $this->getParameter('notify_url');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setNotifyUrl($value)
    {
        return $this->setParameter('notify_url', $value);
    }


    /**
     * @return mixed
     */
    public function getTimestamp()
    {
        return $this->getParameter('timestamp');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setTimestamp($value)
    {
        return $this->setParameter('timestamp', $value);
    }


    /**
     * @return mixed
     */
    public function getAppAuthToken()
    {
        return $this->getParameter('app_auth_token');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setAppAuthToken($value)
    {
        return $this->setParameter('app_auth_token', $value);
    }


    /**
     * @return mixed
     */
    public function getSysServiceProviderId()
    {
        return $this->getParameter('sys_service_provider_id');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setSysServiceProviderId($value)
    {
        return $this->setParameter('sys_service_provider_id', $value);
    }


    /**
     * @return mixed
     */
    public function getAlipayPublicKey()
    {
        return $this->getParameter('alipay_public_key');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setAlipayPublicKey($value)
    {
        return $this->setParameter('alipay_public_key', $value);
    }


    /**
     * @return mixed
     */
    public function getEndpoint()
    {
        return $this->getParameter('endpoint');
    }


    /**
     * @return mixed
     */
    public function getAlipaySdk()
    {
        return $this->getParameter('alipay_sdk');
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setAlipaySdk($value)
    {
        return $this->setParameter('alipay_sdk', $value);
    }


    /**
     * @return AbstractAopGateway
     * @throws InvalidRequestException
     */
    public function production()
    {
        return $this->setEnvironment('production');
    }


    /**
     * @param $value
     *
     * @return $this
     * @throws InvalidRequestException
     */
    public function setEnvironment($value)
    {
        $env = strtolower($value);

        if (! isset($this->endpoints[$env])) {
            throw new InvalidRequestException('The environment is invalid');
        }

        $this->setEndpoint($this->endpoints[$env]);

        return $this;
    }


    /**
     * @param $value
     *
     * @return $this
     */
    public function setEndpoint($value)
    {
        return $this->setParameter('endpoint', $value);
    }


    /**
     * @return AbstractAopGateway
     * @throws InvalidRequestException
     */
    public function sandbox()
    {
        return $this->setEnvironment('sandbox');
    }


    /**
     * @noinspection PhpDocRedundantThrowsInspection
     *
     * @param array $parameters
     *
     * @return AopCompletePurchaseRequest|AbstractRequest
     * @throws InvalidRequestException
     */
    public function completePurchase(array $parameters = [])
    {
        return $this->createRequest(AopCompletePurchaseRequest::class, $parameters);
    }


    /**
     * @noinspection PhpDocRedundantThrowsInspection
     *
     * @param array $parameters
     *
     * @return AopCompleteRefundRequest|AbstractRequest
     * @throws InvalidRequestException
     */
    public function completeRefund(array $parameters = [])
    {
        return $this->createRequest(AopCompleteRefundRequest::class, $parameters);
    }


    /**
     * Query Order Status
     *
     * @param array $parameters
     *
     * @return AopTradeQueryRequest|AbstractRequest
     */
    public function query(array $parameters = [])
    {
        return $this->createRequest(AopTradeQueryRequest::class, $parameters);
    }


    /**
     * Refund
     *
     * @param array $parameters
     *
     * @return AopTradeRefundRequest|AbstractRequest
     */
    public function refund(array $parameters = [])
    {
        return $this->createRequest(AopTradeRefundRequest::class, $parameters);
    }


    /**
     * Query Refund Status
     *
     * @param array $parameters
     *
     * @return AopTradeRefundQueryRequest|AbstractRequest
     */
    public function refundQuery(array $parameters = [])
    {
        return $this->createRequest(AopTradeRefundQueryRequest::class, $parameters);
    }


    /**
     * Close Order
     *
     * @param array $parameters
     *
     * @return AopTradeCloseRequest|AbstractRequest
     */
    public function close(array $parameters = [])
    {
        return $this->createRequest(AopTradeCloseRequest::class, $parameters);
    }


    /**
     * Cancel Order
     *
     * @param array $parameters
     *
     * @return AopTradeCancelRequest|AbstractRequest
     */
    public function cancel(array $parameters = [])
    {
        return $this->createRequest(AopTradeCancelRequest::class, $parameters);
    }


    /**
     * Transfer To Account
     *
     * @param array $parameters
     *
     * @return AopTransferToAccountRequest|AbstractRequest
     */
    public function transfer(array $parameters = [])
    {
        return $this->createRequest(AopTransferToAccountRequest::class, $parameters);
    }


    /**
     * Query Transfer Status
     *
     * @param array $parameters
     *
     * @return AopTransferToAccountQueryRequest|AbstractRequest
     */
    public function transferQuery(array $parameters = [])
    {
        return $this->createRequest(AopTransferToAccountQueryRequest::class, $parameters);
    }


    /**
     * Settle
     *
     * @param array $parameters
     *
     * @return AopTradeCancelRequest|AbstractRequest
     */
    public function settle(array $parameters = [])
    {
        return $this->createRequest(AopTradeOrderSettleRequest::class, $parameters);
    }


    /**
     * @param array $parameters
     *
     * @return AbstractRequest
     */
    public function queryBillDownloadUrl(array $parameters = [])
    {
        return $this->createRequest(DataServiceBillDownloadUrlQueryRequest::class, $parameters);
    }

    /**
     * ----------- Alipay csr supports below ----------
     */


    /**
     * 支付宝支付CSR证书参数
     */
    public function setAppCertSN($value)
    {
        if(is_file($value)){
            return $this->setParameter('app_cert_sn',$this->getCertSN($value));
        }
        return $this->setParameter('app_cert_sn',$value);
    }


    public function getAppCertSN()
    {
        return $this->getParameter('app_cert_sn');
    }

    
    public function setAlipayRootCertSN($value)
    {
        if(is_file($value)){
           return $this->setParameter('alipay_root_cert_sn',$this->getRootCertSN($value));
        }
        return $this->setParameter('alipay_root_cert_sn',$value);
    }

    public function getAlipayRootCertSN()
    {
        return $this->getParameter('alipay_root_cert_sn');
    }


    function array2string($array)
    {
        $string = [];
        if ($array && is_array($array)) {
            foreach ($array as $key => $value) {
                $string[] = $key . '=' . $value;
            }
        }
        return implode(',', $string);
    }


    /**
     * 从证书中提取序列号
     * @param $cert
     * @return string
     */
    public function getCertSN($certPath)
    {
        $cert = file_get_contents($certPath);
        $ssl = openssl_x509_parse($cert);
        $SN = md5($this->array2string(array_reverse($ssl['issuer'])) . $ssl['serialNumber']);
        return $SN;
    }

     /**
     * 提取根证书序列号
     * @param $cert  根证书
     * @return string|null
     */
    public function getRootCertSN($certPath)
    {
        $cert = file_get_contents($certPath);
        $this->alipayRootCertContent = $cert;
        $array = explode("-----END CERTIFICATE-----", $cert);
        $SN = null;
        for ($i = 0; $i < count($array) - 1; $i++) {
            $ssl[$i] = openssl_x509_parse($array[$i] . "-----END CERTIFICATE-----");
            if(strpos($ssl[$i]['serialNumber'],'0x') === 0){
                $ssl[$i]['serialNumber'] = $this->hex2dec($ssl[$i]['serialNumber']);
            }
            if ($ssl[$i]['signatureTypeLN'] == "sha1WithRSAEncryption" || $ssl[$i]['signatureTypeLN'] == "sha256WithRSAEncryption") {
                if ($SN == null) {
                    $SN = md5($this->array2string(array_reverse($ssl[$i]['issuer'])) . $ssl[$i]['serialNumber']);
                } else {

                    $SN = $SN . "_" . md5($this->array2string(array_reverse($ssl[$i]['issuer'])) . $ssl[$i]['serialNumber']);
                }
            }
        }
        return $SN;
    }

    /**
     * 从证书中提取公钥
     * @param $cert
     * @return mixed
     */
    public function getPublicKey($certPath)
    {
        $cert = file_get_contents($certPath);
        $pkey = openssl_pkey_get_public($cert);
        $keyData = openssl_pkey_get_details($pkey);
        $public_key = str_replace('-----BEGIN PUBLIC KEY-----', '', $keyData['key']);
        $public_key = trim(str_replace('-----END PUBLIC KEY-----', '', $public_key));
        return $public_key;
    }
}
