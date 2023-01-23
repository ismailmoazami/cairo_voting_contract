%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.math import assert_not_zero

from openzeppelin.access.ownable.library import Ownable
from openzeppelin.security.pausable.library import Pausable

struct voteCounting {
    votes_yes: felt,
    votes_no: felt,
}

struct voterInfo {
    allowed: felt,
}

@storage_var
func voting_status() -> (res: voteCounting) {
}

@storage_var
func voter_info(address: felt) -> (res: voterInfo) {
}

@storage_var
func registered_user(address: felt) -> (is_registered: felt) {
}

func register_users{syscall_ptr : felt*,
                    pedersen_ptr : HashBuiltin*,
                    range_check_ptr,}
                    (registered_addressed_len: felt, registered_addresses) {
    if (registered_addresses_len == 0){
        return ();
    }

    let voter_info_struct = voterInfo(allowed=1);
    
    registered_user(registered_addresses[registered_addresses_len - 1], 1);
    voter_info.write(registered_addresses[registered_addresses_len - 1], voter_info_struct);

    return register_users(registered_addresses_len - 1, registered_addresses);
}

func vote_allowed{syscall_ptr: felt*, range_check_ptr}(info: voterInfo){
    with_attr error("User not allowed to vote!") {
        assert_not_zero(info.allowed);
    }
    return();
}

@external 
func vote{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(vote: felt) 
{
    alloc_locals; 
    Pausable.assert_not_paused();
    let (user_address) = get_caller_address()
    let (info) = voter_info(user_address);
    vote_allowed(info);

    updated_info = voterInfo(allowed=0);
    voter_info.write(user_address, updated_info);

    let (status) = voting_status();
    let (new_status) :voteCounting;

    if(vote == 0) {
        assert new_status.votes_no = status.votes_no + 1;
        assert new_status.votes_yes = status.votes_yes;
    }if(vote==1){
        assert new_status.votes_yes = status.votes_yes + 1;
        assert new_status.votes_no = status.votes_no;
    }else{
        return();
    }

    voting_status.write(new_status);
    return ();
}

@view 
func get_voting_status{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}() -> (current_voting_status: voteCounting) {
    return (current_voting_status=voting_status.read());
}

@view 
func get_user_voting_info{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,range_check_ptr}(user_address: felt) -> (voter_current_status: voterInfo) {
    return (voter_current_status = voter_info.read(user_address));
}

