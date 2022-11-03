use serde::de::DeserializeOwned;
use serde::Serialize;

use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128, CosmosMsg, BankMsg, coins, Empty, WasmMsg, to_binary, from_binary};

use cw2::set_contract_version;
use cw721::{ContractInfoResponse, CustomMsg, Cw721Execute, Cw721ReceiveMsg, Expiration};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, MintMsg, Cw20ExecuteMsg, Cw20ReceiveMsg, CW20HookMsg, Cw721ExecuteMsg};
use crate::state::{Approval, Cw721Contract, TokenInfo};

// Version info for migration
const CONTRACT_NAME: &str = "crates.io:cw721-gift";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

impl<'a, T, C, E, Q> Cw721Contract<'a, T, C, E, Q>
where
    T: Serialize + DeserializeOwned + Clone,
    C: CustomMsg,
    E: CustomMsg,
    Q: CustomMsg,
{
    pub fn instantiate(
        &self,
        deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        msg: InstantiateMsg,
    ) -> StdResult<Response<C>> {
        set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

        let info = ContractInfoResponse {
            name: msg.name,
            symbol: msg.symbol,
            price: msg.price
        };
        self.contract_info.save(deps.storage, &info)?;
        let minter = deps.api.addr_validate(&msg.minter)?;
        self.minter.save(deps.storage, &minter)?;
        Ok(Response::default())
    }

    pub fn execute(
        &self,
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        msg: ExecuteMsg<T, E>,
    ) -> Result<Response<C>, ContractError> {
        match msg {
            ExecuteMsg::Mint(msg) => self.mint(deps, env, info, msg),
            ExecuteMsg::Approve {
                spender,
                token_id,
                expires,
            } => self.approve(deps, env, info, spender, token_id, expires),
            ExecuteMsg::Revoke { spender, token_id } => {
                self.revoke(deps, env, info, spender, token_id)
            }
            ExecuteMsg::ApproveAll { operator, expires } => {
                self.approve_all(deps, env, info, operator, expires)
            }
            ExecuteMsg::RevokeAll { operator } => self.revoke_all(deps, env, info, operator),
            ExecuteMsg::TransferNft {
                recipient,
                token_id,
            } => self.transfer_nft(deps, env, info, recipient, token_id),
            ExecuteMsg::SendNft {
                contract,
                token_id,
                msg,
            } => self.send_nft(deps, env, info, contract, token_id, msg),
            ExecuteMsg::Burn { token_id } => self.burn(deps, env, info, token_id),
            ExecuteMsg::Claim { token_id } => self.claim(deps, env, info, token_id),
            ExecuteMsg::Receive(msg) => self.execute_receive_cw20(deps, env, info, msg),
            ExecuteMsg::Extension { msg: _ } => Ok(Response::default()),
        }
    }
}

// TODO pull this into some sort of trait extension??
impl<'a, T, C, E, Q> Cw721Contract<'a, T, C, E, Q>
where
    T: Serialize + DeserializeOwned + Clone,
    C: CustomMsg,
    E: CustomMsg,
    Q: CustomMsg,
{   
    /// Creation of the gift card.  
    /// If 2.5 USDC is supplied to the contract then the user is allowed to mint a gift card
    /// The rest of the native tokens are added to the gift card to be claimed by the user
    pub fn mint(
        &self,
        deps: DepsMut,
        _env: Env,
        info: MessageInfo,
        msg: MintMsg<T>,
    ) -> Result<Response<C>, ContractError> {
        let state = self.contract_info.load(deps.storage)?;
        let minter = self.minter.load(deps.storage)?;
        // Check if funds are enough
        if info.funds[0].denom != "uusdcx" || info.funds[0].amount <= state.price {
            return Err(ContractError::Unauthorized {  })
        }
        
        // Check native tokens sent with the function to add as gift
        let amount = info.funds[0].amount.checked_sub(state.price).unwrap();
        // create the token
        let token = TokenInfo {
            owner: deps.api.addr_validate(&msg.owner)?,
            sender: deps.api.addr_validate(&info.sender.to_string())?,
            approvals: vec![],
            token_uri: msg.token_uri,
            extension: msg.extension,
            amount_sent: amount,
            fungible_token_address: None,
            fungible_token_amount: None,
            non_fungible_token_address: None,
            token_id: None,
            lockup_time: msg.lockup_time
        };

        self.tokens
            .update(deps.storage, &msg.token_id, |old| match old {
                Some(_) => Err(ContractError::Claimed {}),
                None => Ok(token),
            })?;

        self.increment_tokens(deps.storage)?;

        Ok(Response::new()
            .add_attribute("action", "mint")
            .add_attribute("minter", info.sender.clone())
            .add_attribute("owner", msg.owner)
            .add_attribute("token_id", msg.token_id)
        .add_message(CosmosMsg::Bank(BankMsg::Send { to_address: minter.to_string(), amount: coins(u128::from(state.price), "uusdcx".to_string()) })))
    }

    pub fn claim(
        &self,
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        token_id: String,
    ) -> Result<Response<C>, ContractError> {
        let token = self.tokens.load(deps.storage, &token_id)?;
        self.check_can_send(deps.as_ref(), &env, &info, &token)?;
        if Uint128::from(env.block.time.seconds()) < token.lockup_time {
            return Err(ContractError::Unauthorized {  })
        }
        let amount_to_send = token.amount_sent;
        self.tokens.remove(deps.storage, &token_id)?;
        self.decrement_tokens(deps.storage)?;
        let mut resp: Vec<CosmosMsg<C>> = vec![];
        if amount_to_send > Uint128::zero() {
            resp.push(CosmosMsg::Bank(BankMsg::Send { to_address: info.sender.to_string(), amount: coins(u128::from(amount_to_send), "uusdcx".to_string()) }));
        }

        let fungible_exists = match token.fungible_token_address.clone() {
            Some(_string) => true,
            None => false,
        };
        if fungible_exists {
            resp.push(CosmosMsg::Wasm(WasmMsg::Execute { contract_addr: token.fungible_token_address.unwrap(), msg: to_binary(&Cw20ExecuteMsg::Transfer { recipient: info.sender.to_string(), amount: token.fungible_token_amount.unwrap() })?, funds: vec![] }));
        }

        let non_fungible_exists = match token.non_fungible_token_address.clone() {
            Some(_string) => true,
            None => false,
        };
        if non_fungible_exists {
            resp.push(CosmosMsg::Wasm(WasmMsg::Execute { contract_addr: token.non_fungible_token_address.unwrap(), msg: to_binary(&Cw721ExecuteMsg::TransferNft { recipient: info.sender.to_string(), token_id: token.token_id.unwrap() })?, funds: vec![] }));
        }

        
        Ok(Response::new()
            .add_attribute("action", "claim")
            .add_messages(resp)
            )
    }

    fn private_mint(
        &self,
        deps: DepsMut,
        _env: Env,
        info: MessageInfo,
        msg: MintMsg<T>,
        fungible_token_address: String,
        fungible_token_amount: Uint128
    ) -> Result<Response<C>, ContractError> {
        let state = self.contract_info.load(deps.storage)?;
        let minter = self.minter.load(deps.storage)?;
        // Check if funds are enough
        if info.funds[0].denom != "uusdcx" || info.funds[0].amount <= state.price {
            return Err(ContractError::Unauthorized {  })
        }
        
        // Check native tokens sent with the function to add as gift
        let amount = info.funds[0].amount.checked_sub(state.price).unwrap();
        // create the token
        let token = TokenInfo {
            owner: deps.api.addr_validate(&msg.owner)?,
            sender: deps.api.addr_validate(&info.sender.to_string())?,
            approvals: vec![],
            token_uri: msg.token_uri,
            extension: msg.extension,
            amount_sent: amount,
            fungible_token_address: Some(fungible_token_address),
            fungible_token_amount: Some(fungible_token_amount),
            non_fungible_token_address: None,
            token_id: None,
            lockup_time: msg.lockup_time,
        };

        self.tokens
            .update(deps.storage, &msg.token_id, |old| match old {
                Some(_) => Err(ContractError::Claimed {}),
                None => Ok(token),
            })?;

        self.increment_tokens(deps.storage)?;

        Ok(Response::new()
            .add_attribute("action", "mint")
            .add_attribute("minter", info.sender.clone())
            .add_attribute("owner", msg.owner)
            .add_attribute("token_id", msg.token_id)
        .add_message(CosmosMsg::Bank(BankMsg::Send { to_address: minter.to_string(), amount: coins(u128::from(state.price), "uusdcx".to_string()) })))
    }

    fn private_mint_nft(
        &self,
        deps: DepsMut,
        _env: Env,
        info: MessageInfo,
        msg: MintMsg<T>,
        non_fungible_token_address: String,
        token_id: String,
    ) -> Result<Response<C>, ContractError> {
        let state = self.contract_info.load(deps.storage)?;
        let minter = self.minter.load(deps.storage)?;
        // Check if funds are enough
        if info.funds[0].denom != "uusdcx" || info.funds[0].amount <= state.price {
            return Err(ContractError::Unauthorized {  })
        }
        
        // Check native tokens sent with the function to add as gift
        let amount = info.funds[0].amount.checked_sub(state.price).unwrap();
        // create the token
        let token = TokenInfo {
            owner: deps.api.addr_validate(&msg.owner)?,
            sender: deps.api.addr_validate(&info.sender.to_string())?,
            approvals: vec![],
            token_uri: msg.token_uri,
            extension: msg.extension,
            amount_sent: amount,
            fungible_token_address: None,
            fungible_token_amount: None,
            non_fungible_token_address: Some(non_fungible_token_address),
            token_id: Some(token_id),
            lockup_time: msg.lockup_time
        };

        self.tokens
            .update(deps.storage, &msg.token_id, |old| match old {
                Some(_) => Err(ContractError::Claimed {}),
                None => Ok(token),
            })?;

        self.increment_tokens(deps.storage)?;

        Ok(Response::new()
            .add_attribute("action", "mint")
            .add_attribute("minter", info.sender.clone())
            .add_attribute("owner", msg.owner)
            .add_attribute("token_id", msg.token_id)
        .add_message(CosmosMsg::Bank(BankMsg::Send { to_address: minter.to_string(), amount: coins(u128::from(state.price), "uusdcx".to_string()) })))
    }

    pub fn execute_receive_cw20(
        &self,
        deps: DepsMut, 
        env: Env,
        info: MessageInfo,
        msg: Cw20ReceiveMsg,
    
    ) -> Result<Response<C>, ContractError>  {
    
        match from_binary(&msg.msg)? {
            CW20HookMsg::CreateGift { mint_paramters } => {
                self.private_mint(deps,env,info.clone(),mint_paramters, info.sender.to_string(), msg.amount)
            }
        }
    }

    pub fn execute_receive_cw721(
        &self,
        deps: DepsMut, 
        env: Env,
        info: MessageInfo,
        msg: Cw721ReceiveMsg,
    
    ) -> Result<Response<C>, ContractError>  {
    
        match from_binary(&msg.msg)? {
            CW20HookMsg::CreateGift { mint_paramters } => {
                self.private_mint_nft(deps,env,info.clone(),mint_paramters, info.sender.to_string(),  msg.token_id)
            }
        }
    }


}

impl<'a, T, C, E, Q> Cw721Execute<T, C> for Cw721Contract<'a, T, C, E, Q>
where
    T: Serialize + DeserializeOwned + Clone,
    C: CustomMsg,
    E: CustomMsg,
    Q: CustomMsg,
{
    type Err = ContractError;

    fn transfer_nft(
        &self,
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        recipient: String,
        token_id: String,
    ) -> Result<Response<C>, ContractError> {
        self._transfer_nft(deps, &env, &info, &recipient, &token_id)?;

        Ok(Response::new()
            .add_attribute("action", "transfer_nft")
            .add_attribute("sender", info.sender)
            .add_attribute("recipient", recipient)
            .add_attribute("token_id", token_id))
    }

    fn send_nft(
        &self,
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        contract: String,
        token_id: String,
        msg: Binary,
    ) -> Result<Response<C>, ContractError> {
        // Transfer token
        self._transfer_nft(deps, &env, &info, &contract, &token_id)?;

        let send = Cw721ReceiveMsg {
            sender: info.sender.to_string(),
            token_id: token_id.clone(),
            msg,
        };

        // Send message
        Ok(Response::new()
            .add_message(send.into_cosmos_msg(contract.clone())?)
            .add_attribute("action", "send_nft")
            .add_attribute("sender", info.sender)
            .add_attribute("recipient", contract)
            .add_attribute("token_id", token_id))
    }

    fn approve(
        &self,
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        spender: String,
        token_id: String,
        expires: Option<Expiration>,
    ) -> Result<Response<C>, ContractError> {
        self._update_approvals(deps, &env, &info, &spender, &token_id, true, expires)?;

        Ok(Response::new()
            .add_attribute("action", "approve")
            .add_attribute("sender", info.sender)
            .add_attribute("spender", spender)
            .add_attribute("token_id", token_id))
    }

    fn revoke(
        &self,
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        spender: String,
        token_id: String,
    ) -> Result<Response<C>, ContractError> {
        self._update_approvals(deps, &env, &info, &spender, &token_id, false, None)?;

        Ok(Response::new()
            .add_attribute("action", "revoke")
            .add_attribute("sender", info.sender)
            .add_attribute("spender", spender)
            .add_attribute("token_id", token_id))
    }

    fn approve_all(
        &self,
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        operator: String,
        expires: Option<Expiration>,
    ) -> Result<Response<C>, ContractError> {
        // reject expired data as invalid
        let expires = expires.unwrap_or_default();
        if expires.is_expired(&env.block) {
            return Err(ContractError::Expired {});
        }

        // set the operator for us
        let operator_addr = deps.api.addr_validate(&operator)?;
        self.operators
            .save(deps.storage, (&info.sender, &operator_addr), &expires)?;

        Ok(Response::new()
            .add_attribute("action", "approve_all")
            .add_attribute("sender", info.sender)
            .add_attribute("operator", operator))
    }

    fn revoke_all(
        &self,
        deps: DepsMut,
        _env: Env,
        info: MessageInfo,
        operator: String,
    ) -> Result<Response<C>, ContractError> {
        let operator_addr = deps.api.addr_validate(&operator)?;
        self.operators
            .remove(deps.storage, (&info.sender, &operator_addr));

        Ok(Response::new()
            .add_attribute("action", "revoke_all")
            .add_attribute("sender", info.sender)
            .add_attribute("operator", operator))
    }

    fn burn(
        &self,
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        token_id: String,
    ) -> Result<Response<C>, ContractError> {
        let token = self.tokens.load(deps.storage, &token_id)?;
        self.check_can_send(deps.as_ref(), &env, &info, &token)?;

        self.tokens.remove(deps.storage, &token_id)?;
        self.decrement_tokens(deps.storage)?;

        Ok(Response::new()
            .add_attribute("action", "burn")
            .add_attribute("sender", info.sender)
            .add_attribute("token_id", token_id))
    }

    
}

// helpers
impl<'a, T, C, E, Q> Cw721Contract<'a, T, C, E, Q>
where
    T: Serialize + DeserializeOwned + Clone,
    C: CustomMsg,
    E: CustomMsg,
    Q: CustomMsg,
{
    pub fn _transfer_nft(
        &self,
        deps: DepsMut,
        env: &Env,
        info: &MessageInfo,
        recipient: &str,
        token_id: &str,
    ) -> Result<TokenInfo<T>, ContractError> {
        let mut token = self.tokens.load(deps.storage, token_id)?;
        // ensure we have permissions
        self.check_can_send(deps.as_ref(), env, info, &token)?;
        // set owner and remove existing approvals
        token.owner = deps.api.addr_validate(recipient)?;
        token.approvals = vec![];
        self.tokens.save(deps.storage, token_id, &token)?;
        Ok(token)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn _update_approvals(
        &self,
        deps: DepsMut,
        env: &Env,
        info: &MessageInfo,
        spender: &str,
        token_id: &str,
        // if add == false, remove. if add == true, remove then set with this expiration
        add: bool,
        expires: Option<Expiration>,
    ) -> Result<TokenInfo<T>, ContractError> {
        let mut token = self.tokens.load(deps.storage, token_id)?;
        // ensure we have permissions
        self.check_can_approve(deps.as_ref(), env, info, &token)?;

        // update the approval list (remove any for the same spender before adding)
        let spender_addr = deps.api.addr_validate(spender)?;
        token.approvals = token
            .approvals
            .into_iter()
            .filter(|apr| apr.spender != spender_addr)
            .collect();

        // only difference between approve and revoke
        if add {
            // reject expired data as invalid
            let expires = expires.unwrap_or_default();
            if expires.is_expired(&env.block) {
                return Err(ContractError::Expired {});
            }
            let approval = Approval {
                spender: spender_addr,
                expires,
            };
            token.approvals.push(approval);
        }

        self.tokens.save(deps.storage, token_id, &token)?;

        Ok(token)
    }

    /// returns true iff the sender can execute approve or reject on the contract
    pub fn check_can_approve(
        &self,
        deps: Deps,
        env: &Env,
        info: &MessageInfo,
        token: &TokenInfo<T>,
    ) -> Result<(), ContractError> {
        // owner can approve
        if token.owner == info.sender {
            return Ok(());
        }
        // operator can approve
        let op = self
            .operators
            .may_load(deps.storage, (&token.owner, &info.sender))?;
        match op {
            Some(ex) => {
                if ex.is_expired(&env.block) {
                    Err(ContractError::Unauthorized {})
                } else {
                    Ok(())
                }
            }
            None => Err(ContractError::Unauthorized {}),
        }
    }

    /// returns true iff the sender can transfer ownership of the token
    pub fn check_can_send(
        &self,
        deps: Deps,
        env: &Env,
        info: &MessageInfo,
        token: &TokenInfo<T>,
    ) -> Result<(), ContractError> {
        // owner can send
        if token.owner == info.sender {
            return Ok(());
        }

        // any non-expired token approval can send
        if token
            .approvals
            .iter()
            .any(|apr| apr.spender == info.sender && !apr.is_expired(&env.block))
        {
            return Ok(());
        }

        // operator can send
        let op = self
            .operators
            .may_load(deps.storage, (&token.owner, &info.sender))?;
        match op {
            Some(ex) => {
                if ex.is_expired(&env.block) {
                    Err(ContractError::Unauthorized {})
                } else {
                    Ok(())
                }
            }
            None => Err(ContractError::Unauthorized {}),
        }
    }
}
