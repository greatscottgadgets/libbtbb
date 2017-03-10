set(LATEST_RELEASE "2017-03-R2")

execute_process(
        COMMAND git log -n 1 --format=%h
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        RESULT_VARIABLE GIT_EXIT_ERROR
        ERROR_QUIET
        OUTPUT_VARIABLE GIT_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
if (GIT_EXIT_ERROR)
	# We're probably not in a git repo
	set(RELEASE ${LATEST_RELEASE})
else (GIT_EXIT_ERROR)
	# We're in a git repo
	execute_process(
		COMMAND git status -s --untracked-files=no
		OUTPUT_VARIABLE DIRTY
	)
	if ( NOT "${DIRTY}" STREQUAL "" )
		set(DIRTY_FLAG "*")
	else()
		set(DIRTY_FLAG "")
	endif()
        set(RELEASE "git-${GIT_VERSION}${DIRTY_FLAG}")
endif (GIT_EXIT_ERROR)
