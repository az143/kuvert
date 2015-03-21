package Net::Server::Mail::ESMTP::plainAUTH;
use strict;
use base qw(Net::Server::Mail::ESMTP::Extension);
use MIME::Base64;

use vars qw( $VERSION );
$VERSION = '1.0';

# the following are required by nsme::extension 
# but not documented :(
sub init
{
    my ($self,$parent)=@_;
    $self->{AUTH}=();
    return $self;
}

# the smtp operations we add
sub verb
{
    return ( [ 'AUTH' => \&handle_auth, ],);
}

# what to add to the esmtp capabilities response
sub keyword
{
	return 'AUTH LOGIN PLAIN';
}

# what options to allow for mail from: auth
sub option
{
	return (['MAIL', 'AUTH' => sub { return; }]);
}

# and the actual auth handler
sub handle_auth
{
    my ($self,$args)=@_;
    my ($method,$param);
    $args=~/^(LOGIN|PLAIN)\s*(.*)$/ && (($method,$param)=($1,$2));

    if ($self->{AUTH}->{active})
    {
	delete $self->{AUTH}->{active};
	$self->reply(535, "Authentication phases mixed up.");
	return undef;		# if rv given, server shuts conn!
    }
    elsif ($self->{AUTH}->{completed})
    {
	$self->reply(504,"Already authenticated.");
	return undef;
    }
    elsif (!$method)
    {
	$self->reply(501,"Unknown authentication method.");
	return undef;
    }

    $self->{AUTH}->{active}=$method;
    
    if ($param eq '*') 
    {
	delete $self->{AUTH}->{active};
	$self->reply(501, "Authentication cancelled.");
	return undef;
    }

    if ($method eq 'PLAIN') 
    {
	if ($param)		# plain: immediate with args
	{
	    my (undef,$user,$pwd)=split(/\0/,decode_base64($param),3);
	    if (!$user)
	    {
		delete $self->{AUTH}->{active};
		$self->reply(535, "5.7.8 Authentication failed.");
		return undef;
	    }
	    return run_callback($self,$user,$pwd);
	}
	else			# plain: or empty challenge and then response
	{
	    $self->reply(334," ");
	    # undocumented but crucial: direct stuff to this method
	    $self->next_input_to(\&process_response);
	    return undef;
	}
    }
    elsif ($method eq 'LOGIN') 
    {
	# login is always two challenges
	$self->reply(334, "VXNlcm5hbWU6"); # username
	$self->next_input_to(\&process_response);
	return undef;
    }
}

# runs user-supplied callback on username and password
# responds success if callback succeeds
# sets complete if ok, clears active either way
sub run_callback
{
    my ($self,$user,$pass)=@_;
    my $ok;

    my $ref=$self->{callback}->{AUTH};
    if (ref $ref eq 'ARRAY' && ref $ref->[0] eq 'CODE') 
    {
	my $c=$ref->[0];
	$ok=&$c($self,$user,$pass);
    }
    if ($ok)
    {
	$self->reply(235, "Authentication successful");
	$self->{AUTH}->{completed}=1;
    }
    else
    {
	$self->reply(535,"Authentication failed.");
    }
    delete $self->{AUTH}->{active};
    return undef;
}

# deals with any response, based on active method
sub process_response
{
    my ($self,$args)=@_;

    if (!$self->{AUTH}->{active} || $self->{AUTH}->{completed})
    {
	delete $self->{AUTH}->{active};
	$self->reply(535, "Authentication phases mixed up.");
	return undef;
    }
    if (!$args)
    {
	delete $self->{AUTH}->{active};
	$self->reply(535, "5.7.8 Authentication failed.");
	return undef;
    }
    
    if ($self->{AUTH}->{active} eq "PLAIN")
    {
	# plain is easy: only one response containing everything
	my (undef,$user,$pwd)=split(/\0/,decode_base64($args),3);
	if (!$user)
	{
	    delete $self->{AUTH}->{active};
	    $self->reply(535, "5.7.8 Authentication failed.");
	    return undef;
	}
	return run_callback($self,$user,$pwd);
    }
    elsif ($self->{AUTH}->{active} eq "LOGIN")
    {
	# uglier: two challenges for username+password
	my ($input)=split(/\0/,decode_base64($args));

	# is this the second time round?
	if ($self->{AUTH}->{user})
	{
	    return run_callback($self,$self->{AUTH}->{user},$input);
	}
	else			
	{
	    # nope, first time: save username and challenge
	    # for password
	    $self->{AUTH}->{user}=$input;
	    $self->reply(334, "UGFzc3dvcmQ6"); # password
	    $self->next_input_to(\&process_response);
	    return undef;
	}
    }
    else 
    {
	delete $self->{AUTH}->{active};
	$self->reply(535, "Authentication mixed up.");
	return undef;
    }
}

1;
