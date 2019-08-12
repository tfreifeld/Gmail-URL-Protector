/*Taken from https://gist.github.com/veeenu/6028597*/

var Barrier = function(obj) {

    this._barrier = []; // Holds the elements to wait for
    this._loaded = [];  // Holds the elements which have been loaded

    // Synchronization callback
    this._sync = obj.sync || function() {};

    // Set to true once no other elements are to be added.
    // Prevents firing the sync callback before all elements
    // which need to be checked have been added to the barrier
    this._closed = false;

    var _self = this;

    return {
        push: function(obj) {
            // Check for duplicates
            for(var i in _self._barrier)
                if(_self._barrier[i] === obj)
                    return;

            //console.log('Pushed', obj);

            _self._barrier.push(obj);
        },
        pop: function(obj) {
            // Check for duplicates
            for(var i in _self._loaded)
                if(_self._loaded[i] === obj)
                    return;

            //console.log('Popped', obj);

            _self._loaded.push(obj);

            // If the barrier is still open for pushes,
            // do not check if all elements are loaded.
            // Wait for the user to call close.
            if(!_self._closed)
                return;

            this.close();
        },
        close: function() {
            // This function closes the barrier and performs
            // an initial check. If at the moment of the user's
            // call all elements have already been loaded,
            // fire the callback, else return and wait to be
            // called in the future by this.pop()

            if(!_self._closed)
                //console.log('Closed barrier');

            _self._closed = true;

            var max = _self._barrier.length;

            // Decrease the counter for each match.
            // O(#barrier * #loaded), find a better algorithm?
            for(var i in _self._barrier) {
                for(var j in _self._loaded) {
                    if(_self._barrier[i] === _self._loaded[j])
                        max--;
                }
            }

            // We completed our objective, fire the callback
            if(max === 0) {

                //console.log('Loading complete');

                // Prevent repeated firing and recursion
                // by disabling the callback.
                // Congrats, your object is useless now!
                // TODO add a reactivate() method?
                var _cb = _self._sync;
                _self._sync = function() {};
                _cb();
            }
        }
    };
}

