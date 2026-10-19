export function accountBridge(config) {
  async function call(path, body) {
    const response = await fetch(`${config.bridge}/api/v1/identity${path}`, {
      method: body ? 'POST' : 'GET', redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { authorization: `Bearer ${config.serviceToken}`, ...(body ? {'content-type': 'application/json'} : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!response.ok) { const error = new Error('Account verification failed'); error.status = response.status; const data = await response.json().catch(()=>null); const allowed = ['INVALID_CREDENTIALS','PHONE_NOT_REGISTERED','PHONE_ALREADY_REGISTERED','PHONE_IDENTITY_CONFLICT','ACCOUNT_DISABLED','RATE_LIMITED','INVALID_REGISTRATION']; if (allowed.includes(data?.detail?.errorCode)) error.code = data.detail.errorCode; throw error; }
    const account = await response.json();
    if (typeof account.sub !== 'string' || !/^[0-9a-f-]{36}$/i.test(account.sub) || typeof account.username !== 'string' || !['pending','assigned'].includes(account.tenant_status)) throw new Error('Invalid account response');
    return account;
  }
  return { password: body => call('/authenticate-password', body), phone: body => call('/authenticate-phone', body), register: body => call('/register-phone', body), account: sub => call(`/accounts/${encodeURIComponent(sub)}`) };
}
